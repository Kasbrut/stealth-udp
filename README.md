
# Stealth-UDP

`stealth-udp` is a rudimentary UDP sniffer that captures packets at the
data-link layer on a specific network interface, even when the port is
protected by a firewall.

It collects the data sent by each client into a per-source-IP file inside a
`YYYY-MM-DD-logs` folder, so traffic from different clients is kept separate.

**Disclosure:**
This is a personal learning project. Review the code before running it, and
feel free to suggest changes or improvements.

## Project layout

The code is split into small, single-responsibility modules behind a library
crate, so the core logic is unit-tested without root privileges or a live
network interface:

| Module         | Responsibility                                        |
|----------------|-------------------------------------------------------|
| `cli.rs`       | Parse command-line arguments into `Args`              |
| `capture.rs`   | Select the interface and open the data-link channel   |
| `parser.rs`    | Pure parsing of Ethernet/IPv4/IPv6 UDP frames         |
| `writer.rs`    | Per-IP buffered, append-only file management          |
| `sink.rs`      | Pluggable output formats (`raw`, `jsonl`)             |
| `sniffer.rs`   | Capture/writer threads and shutdown handling          |
| `main.rs`      | Thin entry point that wires everything together       |

Capture and disk writing run on separate threads connected by a bounded
channel, so slow disk I/O never blocks packet capture. Capture goes through
libpcap (the `pcap` crate), which pushes a kernel BPF filter so only UDP
datagrams for the chosen port reach userspace; the interface is opened in
non-promiscuous mode.

## Requirements

Capturing needs libpcap at build/runtime:

- **Linux:** `libpcap` + `libpcap-dev` (e.g. `sudo apt-get install libpcap-dev`)
- **macOS:** ships with the OS, nothing to install
- **Windows:** install [Npcap](https://npcap.com/)

## Building

```bash
cargo build --release
```

## Options

```bash
./stealth-udp --help
```

| Option                     | Description                                                            |
|----------------------------|------------------------------------------------------------------------|
| `-i, --iface <INTERFACE>`  | Network interface to sniff (defaults to the first active, non-loopback)|
| `-p, --port <PORT>`        | UDP destination port to capture (default `12345`)                      |
| `-f, --format <FORMAT>`    | `raw` (append payload bytes) or `jsonl` (one JSON object per datagram)  |
| `--flush-interval <SECS>`  | Seconds between periodic flushes to disk (`0` disables; default `5`)    |

### Output formats

- **`raw`** — appends each datagram's payload bytes to `IP.log`. Suited to
  reconstructing a file streamed by a client across multiple packets (payloads
  are concatenated in arrival order).
- **`jsonl`** — writes one JSON object per datagram to `IP.jsonl`, each with a
  timestamp, source, length and both a UTF-8 and a hex view of the payload.
  Suited to discrete messages.

Both IPv4 and IPv6 sources are supported.

## Running with administrator permissions

Capturing at the data-link layer requires elevated privileges:

```bash
sudo ./stealth-udp [OPTIONS]
```

## Example: sending data

```bash
cat ~/Desktop/test-file.txt | pv | nc -u <IP-ADDRESS> <PORT>
```

## Development

```bash
cargo test                                   # unit tests (no root needed)
cargo clippy --all-targets -- -D warnings    # lints
cargo fmt --check                            # formatting
```
