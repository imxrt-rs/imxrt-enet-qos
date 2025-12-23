# imxrt-enet-qos

A driver targeting the ENET_QOS IP block available on some i.MXRT1170 MCUs.
This driver is compatible with smoltcp.

## Building

Since the driver only targets i.MXRT1170 MCUs, it enables the imxrt-ral's
`"imxrt1176_cm7"` feature by default. You should only include this driver
in firmware targeting that MCU (and core).

This driver enables a minimum set of smoltcp features. You'll also need to
enable other smoltcp features to successfully build. The following invocation
should work during driver development:

```
cargo build --features=smoltcp/socket-udp
```

Your project that uses smoltcp likely enables one of these socket features.

## License

MIT or Apache 2.0.
