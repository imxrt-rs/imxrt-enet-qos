# imxrt-enet-qos

A driver targeting the ENET_QOS IP block available on some i.MXRT1170 MCUs.
This driver is compatible with smoltcp.

## Building

This driver targets i.MXRT1170 MCUs. You must enable one of the supported
imxrt-ral features depending on your target core:

- `imxrt-ral/imxrt1176_cm7` for the Cortex-M7
- `imxrt-ral/imxrt1176_cm4` for the Cortex-M4

This driver is not compatible with any other imxrt-ral chip feature.

Additionally, the driver enables a minimum set of smoltcp features. You'll need
to enable other smoltcp features to successfully build. The following invocation
should work during driver development:

```
cargo build --features=imxrt-ral/imxrt1176_cm7,smoltcp/socket-udp
```

## License

MIT or Apache 2.0.
