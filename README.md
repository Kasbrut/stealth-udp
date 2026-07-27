
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
| `cli.rs`       | Parse arguments + optional JSON config into `Args`    |
| `config.rs`    | Optional JSON config file                             |
| `capture.rs`   | Select the interface and open the libpcap channel     |
| `parser.rs`    | Pure parsing of Ethernet/IPv4/IPv6 UDP frames         |
| `protocol.rs`  | Chunked file-transfer wire protocol (parse + encode)  |
| `writer.rs`    | Per-IP buffered, append-only file management          |
| `sink.rs`      | Pluggable output formats (`raw`, `jsonl`, `file`)     |
| `reassembly.rs`| File reassembly from numbered chunks                  |
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

Build the server and the client template in release mode:

```bash
cargo build --release
```

This produces two binaries in `target/release/`:

- `stealth-udp` — the server/sniffer
- `client` — the client template used by the single-file client workflow (see
  below); for ad-hoc sending you can also use the `send_file` example

Run the checks:

```bash
cargo test                                   # unit + integration tests (no root)
cargo clippy --all-targets -- -D warnings    # lints
cargo fmt --check                            # formatting
```

To build just one binary:

```bash
cargo build --release --bin stealth-udp
cargo build --release --bin client
```

## Options

```bash
./stealth-udp --help
```

| Option                     | Description                                                            |
|----------------------------|------------------------------------------------------------------------|
| `-i, --iface <INTERFACE>`  | Network interface to sniff (defaults to the first active, non-loopback)|
| `-p, --port <PORT>`        | UDP destination port to capture (default `12345`)                      |
| `-f, --format <FORMAT>`    | `raw`, `jsonl` or `file` (see below; default `raw`)                    |
| `--flush-interval <SECS>`  | Seconds between periodic flushes to disk (`0` disables; default `5`)    |
| `--transfer-timeout <SECS>`| Idle seconds before an incomplete file transfer is dropped (`0` disables; default `300`) |
| `-c, --config <FILE>`      | JSON config file; CLI flags override its values                        |

### Output formats

- **`raw`** — appends each datagram's payload bytes to `IP.log`. A quick way to
  capture a stream when packet order is already guaranteed.
- **`jsonl`** — writes one JSON object per datagram to `IP.jsonl`, each with a
  timestamp, source, length and both a UTF-8 and a hex view of the payload.
  Suited to discrete messages.
- **`file`** — reassembles files streamed with the chunked transfer protocol
  (`protocol.rs`). The client announces a file (name, size, chunk size) and
  sends numbered chunks; the server places each chunk at its offset, so it
  tolerates reordering, duplication and loss. Completed files land in
  `logs/<IP>/<name>`; incomplete ones keep a `.part` file and the missing
  chunks are logged on shutdown. See the `send_file` example for a client.

Both IPv4 and IPv6 sources are supported.

### Config file

```json
{ "interface": "en0", "port": 12345, "format": "file", "flush_interval": 5 }
```

Run with `--config path/to/config.json`. Any value also passed on the command
line takes precedence over the file.

### Sending a file (reassembly mode)

Run the server with `--format file`, then use the example client:

```bash
cargo run --example send_file -- <HOST:PORT> ./some-file.bin
```

Because the channel is one-way (no retransmission), the client has several
knobs to survive loss and verify the result:

| Client option      | Effect                                                                 |
|--------------------|------------------------------------------------------------------------|
| `--chunk-size N`   | Payload bytes per packet (default 1400)                                |
| `--repeat N`       | Send each packet N times back-to-back (default 2)                      |
| `--passes N`       | Send the whole file N times; spaced passes resist *burst* loss better  |
| `--delay MICROS`   | Pause after each send (pacing) to avoid overrunning buffers            |
| `--fec N`          | Emit one XOR parity packet per N chunks; the server rebuilds a single lost chunk per group |
| `--compress`       | DEFLATE-compress the file before sending (fewer packets on the wire)   |

Every transfer also carries a SHA-256 of the original file; the server verifies
it on completion and, on mismatch, keeps the `.part` instead of writing the
final file. Idle incomplete transfers are dropped after `--transfer-timeout`
(server side), keeping their `.part`.

Example — compressed, with FEC and three passes:

```bash
cargo run --example send_file -- <HOST:PORT> ./big.bin --compress --fec 8 --passes 3
```

### Encryption (optional)

Traffic can be end-to-end encrypted so a passive observer cannot read it. It
uses sealed boxes (X25519 + XChaCha20-Poly1305): the client encrypts to the
server's public key with a fresh ephemeral key per message (forward secrecy),
and no handshake is needed — a good fit for the one-way channel.

Each client gets its own server-side key pair, so clients share nothing and any
client can be revoked by removing its key from the keyring.

```bash
# 1. On the server: create a client key pair (appends the private key to the
#    keyring, prints the public key to give to that client).
./stealth-udp --gen-client alice --keyring server.keys

# 2. Run the server with decryption enabled.
sudo ./stealth-udp --keyring server.keys -f file

# 3. On the client: encrypt using the printed public key.
cargo run --example send_file -- <HOST:PORT> ./secret.bin --server-key <PUBLIC_HEX>
```

Note: this provides confidentiality, not sender authentication — the public key
is not a secret, so anyone who has it can send. Authenticating *which* client
sent would require per-client signing keys (a possible future addition).

### Single-file client (embedded key)

Instead of shipping a client binary plus a key file, the server can bake a
client's public key directly into a pre-compiled client binary, so each user
gets one self-contained file. The template is built once; provisioning patches
a copy — no recompilation.

```bash
# Build the client template once.
cargo build --release --bin client

# Provision a client: generates the key pair, stores the private key in the
# keyring, and writes a ready-to-run client with the public key embedded.
./stealth-udp --gen-client alice --keyring server.keys \
    --client-template target/release/client --client-out client-alice

# The provisioned client needs no key argument:
./client-alice <HOST:PORT> ./secret.bin
./client-alice --show-key          # inspect the embedded public key
```

Notes: the provisioned binary is specific to the template's OS/architecture.
On macOS the patched binary is re-signed ad-hoc automatically (patching
invalidates the signature, which is fatal on Apple Silicon).

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
