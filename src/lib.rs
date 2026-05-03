//! A basic driver for the ENET QOS IP block.
//!
//! The driver is intended for integration with smoltcp. It uses hardware checksumming
//! as much as possible. It was designed by following the MIMXRT1170 reference manual.
//!
//! # Limitations
//!
//! The implementation assumes that all global memory *that you allocate* for this driver
//! is placed in non-cacheable memory. The driver will not flush any cache lines before
//! coordinating with a DMA controller.
//!
//! This driver does not utilize any TCP / UDP hardware offoading, besides checksumming.
//! Your network stack is expected to achieve this goal.
//!
//! This driver fixes itself to full duplex, 100MBit. Given this speed limitation, the driver
//! only uses one DMA channel.
//!
//! The driver expects you to poll for packets through its `smoltcp` implementation.
//! Interrupts are disabled, and there's no interface to enable them.
//!
//! There's no VLAN support.

#![no_std]

use core::{
    cell::{Cell, UnsafeCell},
    sync::atomic::{AtomicU32, Ordering},
};
use imxrt_ral as ral;

/// A MAC address.
pub type MacAddress = [u8; 6];

/// An allocation for receiving and transmitting data.
///
/// The allocation is 8 byte aligned. Alignment is required to prevent the hardware
/// from writing dummy data into our memory. See chapter 61.3.1.1.2 for details.
/// Don't be fooled by that opening "alignment doesn't matter" claim; the hardware
/// will write garbage data into our memory.
///
/// Why 8 bytes? The memory interconnect is a 64-bit AXI bus, and the amount of
/// dummy data pumped into memory is a function of the AXI bus. How do I know it's
/// a 64 bit AXI bus? Look at Figure 33-2 in the RM. It's understood that a bus
/// master (like `ENET_QOS`) can access OCRAM through the `FlexRAM` controller.
/// The figure reveals that the bus is an AXI64.
#[repr(align(8))]
struct Buffer<const N: usize>(UnsafeCell<[u8; N]>);

impl<const N: usize> Buffer<N> {
    /// Allocate a buffer filled with zeros.
    const fn new() -> Self {
        Self(UnsafeCell::new([0; N]))
    }
}

// Safety: We coordinate ownership with the DMA controller
// using descriptors. Software can only access a mutable slice
// of the buffer when the DMA controller does not own the
// descriptor. Thanks to its token design, smoltcp prevents
// us from forming multiple mutable slices to the same data.
unsafe impl<const N: usize> Sync for Buffer<N> {}

/// Communicates TX / RX buffer information with the DMA controller.
///
/// Users place this in normal memory, not device memory. We'll
/// use fences and memory ordering to make sure the DMA controller
/// knows the modifications to this allocation.
///
/// An element of the array is one of the four [T|R]DES fields. The
/// interpretation of the field depends on your step in the DMA
/// controller setup / usage. In this driver, we only interpret
/// the descriptor as a read format or a write-back format. The
/// context format isn't considered.
type Descriptor = [AtomicU32; 4];

/// An aligned storage for descriptors.
///
/// Alignment due to the same requirements documented on
/// [`Buffer`].
#[repr(align(8))]
struct DescriptorList<const N: usize>([Descriptor; N]);

/// Produce, at compile time, a list of descriptors.
const fn zero_descriptor_list<const N: usize>() -> DescriptorList<N> {
    /// Atomic32 isn't copy-able, so we need another way
    /// to initialize the array arguments.
    #[expect(clippy::declare_interior_mutable_const, reason = "See above comment")]
    const ZERO_DESCRIPTOR: Descriptor = [const { AtomicU32::new(0) }; 4];
    DescriptorList([ZERO_DESCRIPTOR; N])
}

/// The DMA controller owns this descriptor.
///
/// The ownership isn't known until software updates the tail pointer.
/// Nevertheless, you should stop looking at this descriptor once you
/// set this bit.
const DESC3_OWN: u32 = 1 << 31;

/// This is the first descriptor (FD) for a packet.
///
/// Signaled by software in the TX pathway. Signaled by the DMA
/// controller in the RX pathway.
const DESC3_FIRST_DESCRIPTOR: u32 = 1 << 29;

/// This is the last descriptor (LD) for a packet.
///
/// Signaled by software in the TX pathway. Signaled by the DMA
/// controller in the RX pathway.
const DESC3_LAST_DESCRIPTOR: u32 = 1 << 28;

/// Error summary bit.
///
/// Indicates that another error bit is set for this descriptor.
/// This is a quick way to check for TX and RX descriptor issues,
/// but it's not very helpful by itself.
const DESC3_ERROR_SUMMARY: u32 = 1 << 15;

/// Perform IP checksumming and insert checksum (CIC) in hardware.
///
/// - Compute the IP header checksum, and insert it.
/// - Compute the payload checksum, and insert it.
const TDESC3_CIC_ALL_IP_CHECKSUMS: u32 = 0b11 << 16;

/// The bitmask for controlling the TX frame length (FL).
const TDESC3_FRAME_LENGTH_MASK: u32 = 0x7fff;

/// The bitmask for controlling the first TX buffer length (B1L).
const TDESC2_BUFFER_1_LENGTH_MASK: u32 = 0x3fff;

/// Buffer 1 is valid (B1V) for this RX descriptor.
const RDESC3_BUFFER_1_VALID: u32 = 1 << 24;

/// The bitmask for the receive length field.
const RDES3_PACKET_LENGTH_MASK: u32 = 0x7fff;

/// Our buffer size for Ethernet packets.
///
/// Large enough to receive a packet from a malicious IEEE 802.3
/// sender, including its header, but still small enough to not
/// be treated as an `EtherType` enumeration. The size works out
/// nicely for our buffer's alignment
pub const MAX_BUFFER_SIZE: usize = 1024 + 512;

/// Who owns this descriptor?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    /// Software owns the descriptor.
    Software,
    /// Hardware (the DMA controller) owns the descriptor.
    Hardware,
}

impl Owner {
    /// Returns true if the owner is software.
    const fn is_software(self) -> bool {
        matches!(self, Self::Software)
    }
}

/// A ring for interacting with the DMA controller.
///
/// `N` describes the number of descriptors in the ring.
/// You need at least 4.
///
/// Each descriptor is paired with a buffer for sending
/// data. Each buffer is [`MAX_BUFFER_SIZE`].
pub struct Ring<const N: usize> {
    /// Descriptors for coordinating transfers.
    descriptors: DescriptorList<N>,
    /// Buffers assigned to those descriptors.
    buffers: [Buffer<MAX_BUFFER_SIZE>; N],
}

impl<const N: usize> Ring<N> {
    /// Allocate the ring.
    #[must_use]
    pub const fn new() -> Self {
        const {
            assert!(N >= 4, "enet_qos::Ring requires at least 4 descriptors");
        }
        Self {
            descriptors: zero_descriptor_list::<N>(),
            buffers: [const { Buffer::new() }; N],
        }
    }

    /// Convert the ring into its references.
    fn take_ring_ref(&'static mut self) -> RingRef {
        RingRef {
            descriptors: &mut self.descriptors.0,
            buffers: &mut self.buffers,
            index: Cell::new(0),
        }
    }
}

impl<const N: usize> Default for Ring<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal abstraction for managing descriptors and buffers.
///
/// Used for both the RX and TX pathways. The interpretation
/// depends on the operation. This also simplifies type signatures for
/// user code.
struct RingRef {
    /// The descriptor list.
    ///
    /// It's important that this is allocated contiguously, because
    /// that's how the hardware treats it (unless we tell it otherwise).
    /// This is aligned using a `DescriptorList`.
    descriptors: &'static [Descriptor],
    /// A buffer for each descriptor.
    buffers: &'static [Buffer<MAX_BUFFER_SIZE>],
    /// Points to the current descriptor / buffer.
    index: Cell<usize>,
}

impl RingRef {
    /// Return the address to the list's starting descriptor.
    fn start_address(&self) -> u32 {
        let desc: *const Descriptor = self.descriptors.as_ptr();
        desc as u32
    }

    /// Computes the descriptor length for the hardware.
    ///
    /// This is off-by-one. See the documentation for the
    /// transmit and receive rings.
    fn descriptor_ring_len(&self) -> u32 {
        // Cast to u32 is not lossy; you'd need an unreasonable amount
        // of descriptors before this overflowed, and we make sure you
        // have at least one descriptor.
        #[expect(clippy::cast_possible_truncation, reason = "Ring size is reasonable")]
        {
            (self.descriptors.len() - 1) as u32
        }
    }

    /// Advance the software index to the ring's next descriptor.
    ///
    /// Hardware maintains its own index. We tell it how far it can
    /// go by updating tail pointers.
    fn advance_index(&self) {
        self.index
            .set((self.index.get() + 1) % self.descriptors.len());
    }

    /// Returns the descriptor's owner.
    fn owner(&self) -> Owner {
        let desc = self.current_descriptor();
        if desc[3].load(Ordering::Acquire) & DESC3_OWN != 0 {
            Owner::Hardware
        } else {
            Owner::Software
        }
    }

    /// Return the descriptor pointed at by the ring.
    fn current_descriptor(&self) -> &Descriptor {
        let index = self.index.get();
        let Some(descriptor) = self.descriptors.get(index) else {
            // A study of advance_index shows that the index is
            // always in bounds.
            unreachable!();
        };
        descriptor
    }

    /// Return the buffer pointed at by the ring.
    fn current_buffer(&self) -> &Buffer<MAX_BUFFER_SIZE> {
        let index = self.index.get();
        let Some(buffer) = self.buffers.get(index) else {
            // A study of advance_index shows that the index is
            // always in bounds. The collection of buffers and
            // the collection of descriptors have the same size,
            // forced at compile time.
            unreachable!();
        };
        buffer
    }

    /// Prepare a receive operation using the ring's current descriptor.
    fn submit_ring_head(&self, enet_qos: &ral::enet_qos::RegisterBlock) {
        let rdes = self.current_descriptor();
        let buffer: *const Buffer<MAX_BUFFER_SIZE> = self.current_buffer();

        rdes[0].store(buffer as u32, Ordering::Relaxed);
        rdes[1].store(0, Ordering::Relaxed); // Reserved.
        rdes[2].store(0, Ordering::Relaxed); // Unused; only care about a single buffer.

        rdes[3].store(DESC3_OWN | RDESC3_BUFFER_1_VALID, Ordering::Relaxed);

        // Force all descriptor writes to memory.
        core::sync::atomic::fence(Ordering::SeqCst);

        // Update the tail pointer to point at the newly-added descriptor.
        let rdes: *const Descriptor = rdes;
        ral::write_reg!(
            ral::enet_qos,
            enet_qos,
            DMA_CH0_RXDESC_TAIL_POINTER,
            rdes as u32
        );

        self.advance_index();
    }

    /// Indicates if this descriptor has any kind of error.
    fn has_error(&self) -> bool {
        let desc = self.current_descriptor();
        desc[3].load(Ordering::Relaxed) & DESC3_ERROR_SUMMARY != 0
    }
}

/// Section 61.5.1: Initializing DMA
fn initialize_dma_controller(
    enet_qos: &ral::enet_qos::RegisterBlock,
    tx_ring: &RingRef,
    rx_ring: &RingRef,
) {
    // Step 1 and step 2: Reset the DMA controller, and wait for reset to
    // complete.
    ral::write_reg!(ral::enet_qos, enet_qos, DMA_MODE, SWR: 1);
    while ral::read_reg!(ral::enet_qos, enet_qos, DMA_MODE, SWR == 1) {}

    // Step 3: Not touching the SYSBUS_MODE register. Use the default
    // AXI settings.

    // Step 4, 5, and 6:
    //
    // Prepare the receive ring extents, then the descriptors.
    ral::write_reg!(
        ral::enet_qos,
        enet_qos,
        DMA_CH0_RXDESC_LIST_ADDRESS,
        rx_ring.start_address()
    );
    ral::write_reg!(
        ral::enet_qos,
        enet_qos,
        DMA_CH0_RXDESC_RING_LENGTH,
        rx_ring.descriptor_ring_len()
    );

    // Mark all descriptors as owned by the DMA controller.
    // Otherwise, we wouldn't get any packets!
    while rx_ring.owner().is_software() {
        rx_ring.submit_ring_head(enet_qos);
    }

    // Prepare the transmit ring extent, but not the descriptors or
    // tail pointer. We'll prepare those when sending packets.
    ral::write_reg!(
        ral::enet_qos,
        enet_qos,
        DMA_CH0_TXDESC_LIST_ADDRESS,
        tx_ring.start_address()
    );
    ral::write_reg!(
        ral::enet_qos,
        enet_qos,
        DMA_CH0_TXDESC_RING_LENGTH,
        tx_ring.descriptor_ring_len()
    );

    // Step 7:
    //
    // Nothing interesting to do in DMA_CH0_CONTROL. We assume contiguous
    // descriptor allocation, and that's the default values after reset.
    //
    // Set the DMA burst sizes, in terms of AXI bus size (64-bits for
    // this driver.) We'll pick a small number for now, but we should
    // increase this to minimize overhead of the interconnect. Do not
    // exceed half of the FIFO sizes, set later.
    //
    // In the RX path, we set the maximum buffer size for all assigned
    // descriptors. We know this size is correct, since users cannot
    // construct smaller buffers.
    ral::modify_reg!(ral::enet_qos, enet_qos, DMA_CH0_TX_CONTROL,
        TXPBL: 1, // 64 bits per burst.
    );
    ral::modify_reg!(ral::enet_qos, enet_qos, DMA_CH0_RX_CONTROL,
        RXPBL: 1, // 64 bits per burst.
        RBSZ_13_Y: { const {
            // We must have a buffer size that's a multiple of
            // the AXI bus size, in bytes. See field documentation.
            // It's explained elsewhere in this module that we
            // have an AXI64 interconnect.
            assert!(MAX_BUFFER_SIZE.is_multiple_of(8), "Buffer size must be a multiple of 8");

            // Remove the lower 3 bits, since the RBSZ_13_**X**
            // field is three bits wide, RAZ/RO, and accounts
            // for the total size conveyed to the DMA controller.
            #[expect(clippy::cast_possible_truncation, reason = "Evaluation in const would catch truncation")]
            { (MAX_BUFFER_SIZE as u32) >> 3 }
        } },
    );

    // Step 8: Not enabling interrupts. Users will poll for now,
    // or we'll give them an API to set what they need.
    ral::write_reg!(ral::enet_qos, enet_qos, DMA_CH0_INTERRUPT_ENABLE, 0);

    // Step 9: Enable the DMA controller (for channel 0) in TX and RX
    // directions.
    ral::modify_reg!(ral::enet_qos, enet_qos, DMA_CH0_TX_CONTROL, ST: 1);
    ral::modify_reg!(ral::enet_qos, enet_qos, DMA_CH0_RX_CONTROL, SR: 1);
}

/// Section 61.5.2 Initializing MTL Registers
fn initialize_mtl(enet_qos: &ral::enet_qos::RegisterBlock) {
    // Step 1: Not applicable. We're only using one FIFO.
    // Step 2: I don't think it's applicable, since we're not using
    // dynamic arbitration in this driver.

    /// Step 3 and 4:
    ///
    /// We have 8KiB (8192 bytes) available to the TX and RX FIFOs. (See
    /// 61.3.1.2 in the RM). We can't directly access that; however, we
    /// can maximimize its utilization by storing-and-forwarding packets.
    /// See 61.7.1.393.3 for details. We express the value in blocks of
    /// 256 bytes, minus one (there's always one 256 block allocated).
    ///
    /// Store-and-forward also lets us enable hardware checksumming.
    #[expect(clippy::integer_division, reason = "8192 is a multiple of 256")]
    const Q0_FULLY_ALLOCATED: u32 = (8192 / 256) - 1;
    ral::modify_reg!(ral::enet_qos, enet_qos, MTL_TXQ0_OPERATION_MODE,
        TQS: Q0_FULLY_ALLOCATED,
        TSF: ENABLE, // Store-and-forward.
        TXQEN: ENABLE, // Enable this FIFO.
    );
    ral::modify_reg!(ral::enet_qos, enet_qos, MTL_RXQ0_OPERATION_MODE,
        RQS: Q0_FULLY_ALLOCATED,
        RSF: ENABLE, // Store-and-forward.
    );
    ral::modify_reg!(ral::enet_qos, enet_qos, MAC_RXQ_CTRL0,
        RXQ0EN: EN_DCB_GEN, // Enable RX FIFO 0.
    );

    // Step 5: Not applicable. We've initialized all queues required for
    // this driver.
}

/// Section 61.5.3 Initializing MAC
fn initialize_mac(enet_qos: &ral::enet_qos::RegisterBlock, mac_address: MacAddress) {
    // Step 1: program our single MAC address.
    // Write order matters; the write on LOW causes
    // the hardware to internally update the MAC address
    // across both registers. See the RM for details.
    //
    // Note that address 0 is always enabled, so we're not
    // writing the high bit.
    ral::write_reg!(
        ral::enet_qos,
        enet_qos,
        MAC_ADDRESS0_HIGH,
        (u32::from(mac_address[5]) << 8) | u32::from(mac_address[4])
    );
    ral::write_reg!(
        ral::enet_qos,
        enet_qos,
        MAC_ADDRESS0_LOW,
        (u32::from(mac_address[3]) << 24)
            | (u32::from(mac_address[2]) << 16)
            | (u32::from(mac_address[1]) << 8)
            | u32::from(mac_address[0])
    );

    // Step 2: See inline comments. This mostly affects the receive
    // path.
    ral::modify_reg!(ral::enet_qos, enet_qos, MAC_PACKET_FILTER,
        // Receive All. It's not promiscuous mode.
        // This acts on the filter, whereas promiscuous mode
        // bypassess the filter. If enabled, the RX stats would
        // update.
        //
        // We don't need / want this.
        RA: DISABLE,
        // Drop non-TCP/UDP over IP packets.
        //
        // It would be unexpected to drop these, so we forward them
        // up into software.
        DNTU: FWD,
        // Layer 3 and layer 4 filter enable.
        //
        // Yup, this IP can execute parts of a network stack
        // in hardware. Too bad software expects to do that.
        IPFE: DISABLE,
        // VLAN tag filter enable.
        //
        // No support for VLANs in today's driver.
        VTFE: DISABLE,
        // We need none of
        //
        // - Hash or Perfect filter
        // - Hash multicast
        // - Hash Unicast
        //
        // Let the hardware directly compare our MAC to the destination
        // MAC.
        HPF: DISABLE,
        HMC: DISABLE,
        HUC: DISABLE,
        // Source address filter.
        //
        // Turn this on. Drop packets that don't contain our MAC address
        // as the source. This shouldn't affect broadcast packets; we keep
        // those enabled.
        SAF: ENABLE,
        // Invert the source address filter.
        //
        // Nah; we don't want to receive everyone else's packet except for
        // our own. (There's probably clever ways to abuse the statistics
        // engine when using this with receive all...)
        SAIF: DISABLE,
        // Pass control packets.
        //
        // Bring everything up for software to handle.
        PCF: FW_PASS,
        // Disable broadcast packets.
        //
        // This is very tricky, so here it goes: we want broadcast packets.
        // So, enable reception of broadcast packets *by* *writing* *zero*
        // to this field.
        DBF: ENABLE,
        // Pass multicast packets.
        PM: ENABLE,
        // Destination address inverse filter.
        //
        // Keep this normal (disabled). Not really sure what this does...
        DAIF: DISABLE,
        // Promiscuous mode.
        //
        // We're not here to spy on the network.
        PR: DISABLE,
    );

    // Step 3: See inline notes. This also sets RX flow control.
    ral::modify_reg!(ral::enet_qos, enet_qos, MAC_Q0_TX_FLOW_CTRL,
        // Disable transmit flow control.
        TFE: DISABLE,
        // Send this as the pause quanta for the pause frame
        // (512 * PT bit times on the wire). Scaling factor is arbitrary.
        PT: 512,
    );
    ral::modify_reg!(ral::enet_qos, enet_qos, MAC_RX_FLOW_CTRL,
        // Receive flow control.
        RFE: DISABLE,
    );

    // Step 4: Disable all interrupts. Users will poll until we give
    // them something better.
    ral::write_reg!(ral::enet_qos, enet_qos, MAC_INTERRUPT_ENABLE, 0);

    // Step 5: See inline comments. There's too many configurations
    // to list out explicitly, so see the reference manual for the
    // range of options.
    ral::modify_reg!(ral::enet_qos, enet_qos, MAC_CONFIGURATION,
        // Source address insert / replacement.
        //
        // Not needed. smoltcp does it for us.
        SARC: 0,
        // IP checksum enable.
        //
        // Yes please; we can tell smoltcp we're doing this.
        IPC: ENABLE,
        // CRC stripping (in the RX path).
        //
        // Yes please. This doesn't disable the checksum. We simply
        // won't receive these bytes in our buffer.
        CST: ENABLE,
        // Automatic pad / CRC stripping.
        //
        // Do it; we don't need the packet padding / CRC in software.
        ACS: ENABLE,
        // Port select.
        //
        // We're throttling to either 10Mbps or 100Mbps, specified
        // later.
        PS: BF_10_100M,
        // Speed.
        //
        // We're throttling to 100Mbps.
        FES: MBPS_100_2500M,
        // Full duplex mode.
        DM: FDUPLX,
        // We can't support loopback in full duplex mode.
        LM: DISABLE,
    );

    // Step 6: The user enables the MAC, so skip this step.
}

/// The Ethernet QOS driver.
pub struct EnetQos {
    /// Our peripheral instance, owning all registers.
    #[expect(clippy::struct_field_names, reason = "preferred name")]
    enet_qos: ral::enet_qos::Instance<{ ral::SOLE_INSTANCE }>,
    /// Reference to user-allocated transmit ring.
    tx_ring: RingRef,
    /// Reference to user-allocated receive ring.
    rx_ring: RingRef,
}

impl EnetQos {
    /// Construct a driver with configurable TX and RX rings.
    ///
    /// `bus_clk_root_hz` is the frequency, in Hz, of `BUS_CLK_ROOT`.
    pub fn new<const TX: usize, const RX: usize>(
        enet_qos: ral::enet_qos::Instance<{ ral::SOLE_INSTANCE }>,
        tx_ring: &'static mut Ring<TX>,
        rx_ring: &'static mut Ring<RX>,
        bus_clk_root_hz: u32,
        mac_address: &MacAddress,
    ) -> Self {
        // Reduces exclusive to shared references. From
        // now on, we use types that can be mutably shared
        // in Rust.
        let tx_ring = tx_ring.take_ring_ref();
        let rx_ring = rx_ring.take_ring_ref();

        initialize_dma_controller(&enet_qos, &tx_ring, &rx_ring);
        initialize_mtl(&enet_qos);
        initialize_mac(&enet_qos, *mac_address);
        initialize_mdio_clocks(&enet_qos, bus_clk_root_hz);

        Self {
            enet_qos,
            tx_ring,
            rx_ring,
        }
    }

    /// Enable `true` or disable `false` the MAC.
    pub fn enable_mac(&mut self, enable: bool) {
        ral::modify_reg!(ral::enet_qos, self.enet_qos, MAC_CONFIGURATION,
            TE: u32::from(enable), // codespell-ignore
            RE: u32::from(enable),
        );
    }

    /// Checks if the MDIO bus is busy performing a transaction.
    fn is_mdio_busy(&self) -> bool {
        ral::read_reg!(ral::enet_qos, self.enet_qos, MAC_MDIO_ADDRESS, GB == 1)
    }

    /// Write to the attached PHY through the MDIO interface (Clause 22).
    ///
    /// `phy` is your PHY's address. `reg` is the register, and
    /// `data` is the associated data. The implementation spins until
    /// the MAC has completed the write.
    pub fn mdio_write(&mut self, phy: u8, reg: u8, data: u16) {
        ral::modify_reg!(ral::enet_qos, self.enet_qos, MAC_MDIO_ADDRESS,
            PA: u32::from(phy),
            RDA: u32::from(reg),
            // Write command.
            GOC_1: 0,
            GOC_0: 1,
        );
        ral::write_reg!(ral::enet_qos, self.enet_qos, MAC_MDIO_DATA, u32::from(data));
        ral::modify_reg!(ral::enet_qos, self.enet_qos, MAC_MDIO_ADDRESS, GB: 1);

        while self.is_mdio_busy() {
            core::hint::spin_loop();
        }
    }

    /// Read a register's data from an attached PHY (Clause 22).
    ///
    /// `phy` is your PHY's address. `reg` is the register to read.
    /// The implementation spin until the transaction completes.
    pub fn mdio_read(&mut self, phy: u8, reg: u8) -> u16 {
        ral::modify_reg!(ral::enet_qos, self.enet_qos, MAC_MDIO_ADDRESS,
            PA: u32::from(phy),
            RDA: u32::from(reg),
            // Read command.
            GOC_1: 1,
            GOC_0: 1,
        );

        ral::modify_reg!(ral::enet_qos, self.enet_qos, MAC_MDIO_ADDRESS, GB: 1);

        while self.is_mdio_busy() {
            core::hint::spin_loop();
        }

        let Ok(data) = ral::read_reg!(ral::enet_qos, self.enet_qos, MAC_MDIO_DATA, GD).try_into()
        else {
            // GD is a 16 bit field. read_reg! will mask and offset those
            // 16 bits such that they fit within a u16.
            unreachable!();
        };

        data
    }

    /// Produce a receive token, if one is available.
    fn rx_token(&self) -> Option<RxToken<'_>> {
        while self.rx_ring.owner().is_software() && self.rx_ring.has_error() {
            // We can't trust its data. Re-schedule the
            // descriptor to receive new data. Users can
            // figure out that there was an error by querying
            // the MAC statistics.
            self.rx_ring.submit_ring_head(&self.enet_qos);
        }

        (self.rx_ring.owner().is_software()).then(|| RxToken {
            ring: &self.rx_ring,
            enet_qos: &self.enet_qos,
        })
    }

    /// Produce a transmit token, if one is available.
    fn tx_token(&self) -> Option<TxToken<'_>> {
        (self.tx_ring.owner().is_software()).then(|| TxToken {
            ring: &self.tx_ring,
            enet_qos: &self.enet_qos,
        })
    }
}

/// Select the MDIO clock range, given the bus clock frequency in Hz.
///
/// # Panics
///
/// Panics if `bus_clk_root_hz` cannot be translated into the correct divider
/// value. A safe value for `bus_clk_root_hz` is `bsp::BUS_CLK_ROOT_HZ`.
fn initialize_mdio_clocks(enet_qos: &ral::enet_qos::RegisterBlock, bus_clk_root_hz: u32) {
    use core::ops::Range;

    /// Converts a `MHz` value into `Hz`.
    const fn mhz(mhz: u32) -> u32 {
        mhz * 1000 * 1000
    }

    /// Find the range that includes `bus_clk_root_hz`. The
    /// index of that range is written to the CR field. See
    /// section 61.7.1.42.3 in the RM for details.
    const CSR_CLOCK_RANGES: &[Range<u32>] = &[
        mhz(60)..mhz(100),
        mhz(100)..mhz(150),
        mhz(20)..mhz(35),
        mhz(35)..mhz(60),
        mhz(150)..mhz(250),
        mhz(250)..mhz(300),
        mhz(300)..mhz(500),
        mhz(500)..mhz(800),
    ];

    #[expect(
        clippy::expect_used,
        reason = "The user has misconfigured their system"
    )]
    let cr = CSR_CLOCK_RANGES
        .iter()
        .position(|range| range.contains(&bus_clk_root_hz))
        .expect("User-supplied bus_clk_root_hz is not covered by a MDIO clock range");

    let Ok(cr): Result<u32, _> = cr.try_into() else {
        // cr takes values 0 through 7. All values fit within a u32.
        unreachable!();
    };
    ral::write_reg!(ral::enet_qos, enet_qos, MAC_MDIO_ADDRESS, CR: cr);
}

/// A token for sending packets.
///
/// You probably won't interact with this type directly; it's
/// a `smoltcp` implementation detail.
pub struct TxToken<'r> {
    /// The ring we use for sending data.
    ring: &'r RingRef,
    /// Shared borrow of the registers
    ///
    /// We only access the transmit ring tail.
    enet_qos: &'r ral::enet_qos::RegisterBlock,
}

/// Make sure that the maximum buffer size can fit within the field
/// allocated for the buffer's length. If we can fit the maximum size,
/// then we must be able to fit any smaller size.
const _: () = assert!(
    MAX_BUFFER_SIZE & (TDESC2_BUFFER_1_LENGTH_MASK as usize) == MAX_BUFFER_SIZE,
    "Max buffer could not fit inside its field"
);

impl smoltcp::phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Safety: From the Rust perspective, we're going to acquire an exclusive reference
        // to a buffer from a shared reference, through an UnsafeCell. This is safe, since
        // this is the only point at which we form that exclusive reference. We know that
        // no user of this library can (safely) access that buffer, since the Buffer
        // newtype doesn't expose its member. We can see that this package doesn't form
        // that exclusive reference anywhere else. This code is not reentrant, since the
        // token requires an exclusive reference to the device (the EnetQos driver).
        //
        // We're then going to DMA into some buffer of memory. This is also safe. The
        // driver's interface requires static buffers, so that memory is valid. The interface
        // also requires an exclusive reference to those static buffers, so no one else
        // is looking at that memory.
        unsafe {
            let buffer = self.ring.current_buffer();
            let buffer: &mut [u8; MAX_BUFFER_SIZE] = &mut *buffer.0.get();

            // len comes from the caller, which we can't control.
            // Prevent an out-of-bounds access by clamping the size.
            //
            // If a caller tries to send more data, then they aren't
            // respecting the max packet size (MPS) we set in the
            // device capabilities.
            let len = len.min(MAX_BUFFER_SIZE);

            // When this returns, the user has updated the buffer with data
            // to transmit.
            #[expect(
                clippy::indexing_slicing,
                reason = "len is never more than MAX_BUFFER_SIZE"
            )]
            let result = { f(&mut buffer[..len]) };

            #[expect(
                clippy::cast_possible_truncation,
                reason = "len is never more than MAX_BUFFER_SIZE, and MAX_BUFFER_SIZE fits inside a u32"
            )]
            let len = { len as u32 };

            let tdes = self.ring.current_descriptor();
            // Where's the buffer with data that we're sending?
            tdes[0].store(buffer.as_ptr() as u32, Ordering::Relaxed);
            // Buffer 2, extended buffers are unused.
            tdes[1].store(0, Ordering::Relaxed);
            // How big is that buffer? We know this fits inside the descriptor
            // field; there's an assert for that, above.
            tdes[2].store(TDESC2_BUFFER_1_LENGTH_MASK & len, Ordering::Relaxed);

            tdes[3].store(
                // This descriptor is the first and last descriptor associated
                // with this packet. We're not gathering buffers.
                DESC3_FIRST_DESCRIPTOR | DESC3_LAST_DESCRIPTOR |
                // Enable hardware checksumming for IP headers.
                TDESC3_CIC_ALL_IP_CHECKSUMS |
                // The DMA controller now owns the descriptor.
                DESC3_OWN |
                // Include the total packet length. There's only
                // one packet, so its the length the user wrote.
                (TDESC3_FRAME_LENGTH_MASK & len),
                Ordering::Relaxed,
            );

            // Force all descriptor writes to memory.
            core::sync::atomic::fence(Ordering::SeqCst);

            // Move along to the next descriptor, so we can schedule another
            // transmit operation. We also need to finish the DMA controller
            // update by advancing the tail pointer.
            self.ring.advance_index();

            // This points at the *next* descriptor, since we just advanced
            // the index.
            let tdes: *const Descriptor = self.ring.current_descriptor();
            ral::write_reg!(
                ral::enet_qos,
                self.enet_qos,
                DMA_CH0_TXDESC_TAIL_POINTER,
                tdes as u32
            );

            result
        }
    }
}

/// A token for receiving packets.
///
/// You probably won't interact with this type directly; it's
/// a `smoltcp` implementation detail.
pub struct RxToken<'r> {
    /// The ring for receiving data.
    ring: &'r RingRef,
    /// A shared reference to the registers.
    ///
    /// We only use this to update the receive ring tail.
    enet_qos: &'r ral::enet_qos::RegisterBlock,
}

impl smoltcp::phy::RxToken for RxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        // Safety: There's a similar discussion to the TxToken implementation about
        // forming the exclusive reference from a shared reference. See that comment
        // for details, since it applies here, too.
        //
        // We're forming a slice for a buffer that contains data read from the network.
        // We trust the hardware to tell us how many bytes are valid, and we've checked
        // to make sure we're not reading out-of-bounds.
        unsafe {
            let buffer = self.ring.current_buffer();
            let buffer: &[u8; MAX_BUFFER_SIZE] = &*buffer.0.get();

            let rdes = self.ring.current_descriptor();
            let valid_len = (RDES3_PACKET_LENGTH_MASK & rdes[3].load(Ordering::Acquire)) as usize;

            #[expect(
                clippy::indexing_slicing,
                reason = "Panic is correct; the DMA controller told us too much data is available"
            )]
            let result = { f(&buffer[..valid_len]) };

            // Now that we've read data from this descriptor, we can give it
            // back to the hardware to receive another packet.
            self.ring.submit_ring_head(self.enet_qos);

            result
        }
    }
}

impl smoltcp::phy::Device for EnetQos {
    type RxToken<'a> = RxToken<'a>;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();

        caps.medium = smoltcp::phy::Medium::Ethernet;

        // 1500 bytes in the Ethernet packet (AKA, the IP MTU).
        // 6 bytes for the source MAC.
        // 6 bytes for the destination MAC.
        // 2 bytes for EtherType.
        // Don't include any CRCs.
        // See the smoltcp documentation.
        caps.max_transmission_unit = 1500 + 6 + 6 + 2;

        // How many MTUs of data can we have in flight at a
        // given time? That depends on how many descriptors
        // we've allocated.
        let burst_size = self
            .tx_ring
            .descriptors
            .len()
            .min(self.rx_ring.descriptors.len());
        caps.max_burst_size = Some(burst_size);

        caps.checksum.ipv4 = smoltcp::phy::Checksum::None;
        caps.checksum.udp = smoltcp::phy::Checksum::None;
        caps.checksum.tcp = smoltcp::phy::Checksum::None;
        caps.checksum.icmpv4 = smoltcp::phy::Checksum::None;

        caps
    }

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(RxToken<'_>, TxToken<'_>)> {
        let rx_token = self.rx_token()?;
        let tx_token = self.tx_token()?;
        Some((rx_token, tx_token))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<TxToken<'_>> {
        self.tx_token()
    }
}
