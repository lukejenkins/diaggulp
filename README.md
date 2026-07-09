# diaggulp

> Part of the **[cellular `diag*` toolkit](https://github.com/lukejenkins/cellular#the-diag-toolkit)**: start there for how the capture/decode pieces fit together.

Low-CPU, host-side **Qualcomm DIAG capture**. diaggulp arms the DIAG log
mask and streams the raw HDLC bytes the modem emits straight to a file or
stdout, over USB serial, TCP, or UDP, with minimal host CPU.

## Acknowledgements & prior art

Host-side Qualcomm DIAG capture and decoding was pioneered by projects like
**QCSuper** and **SCAT**. They reverse-engineered and documented this
protocol over many years, and they remain the reference implementations;
diaggulp follows the trail they blazed, and owes them a great deal.

diaggulp is not a replacement for them. It deliberately does one small
thing, the *capture* step, with a low-CPU implementation and an Apache-2.0
license that makes it easy to embed in permissively-licensed pipelines. That
is simply a different set of tradeoffs, not a judgment on theirs. Because the
output is the same HDLC-framed DIAG stream those tools already understand,
diaggulp is built to **compose** with them, not compete.

## Install

```
pip install diaggulp            # capture only
pip install diaggulp[serial]    # + live USB-serial capture support
pip install diaggulp[decode]    # + inline --decode and --pcap-out (GSMTAP pcap)
```

The base install is stdlib-only on the capture path; the `serial` and
`decode` extras pull their requirements lazily, so a plain capture pays for
neither.

## Usage

```
# Capture from a USB-serial DIAG port to a file
diaggulp /dev/ttyUSB0 -o capture.dlf

# Capture to stdout, to pipe into a downstream decoder
diaggulp /dev/ttyUSB0 -o -

# Capture over a network DIAG transport
diaggulp tcp://192.168.1.1:43555 -o capture.dlf

# Capture raw DIAG and also write a live Wireshark pcap (needs the decode extra)
diaggulp /dev/ttyUSB0 -o capture.dlf --pcap-out live.pcap
```

Run `diaggulp --help` for the full option set (transport selection, mask
scope, inline decode, live pcap, NMEA sidecar, and more).

## Output & interoperability

The output is the raw, `0x7E`-delimited HDLC frame stream exactly as the
modem emits it, not a re-framed record format. Point any DIAG consumer that
accepts a raw HDLC/DLF byte stream at it (for example QCSuper's `--dlf`
input, SCAT, or the `diaggrok` decoders).

For a Wireshark-ready view, `--pcap-out PATH` writes a GSMTAP pcap (LTE
RRC/NAS on UDP/4729) live while capturing, alongside a sibling `.nr.pcap`
for NR signalling (Exported-PDU). It runs on a side thread and leaves the
raw `-o` capture untouched; it needs the `decode` extra.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
