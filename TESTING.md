# Testing Guide

A step-by-step protocol to verify `stealth-udp` across all of its options.
Each check lists what to run and what you should see.

Loss, reordering and duplication are hard to force by hand, so they are covered
by the automated test suite (Part A) rather than manually; the manual checks
(Part B onward) focus on everything that is easy to observe end-to-end.

---

## Topology note (important)

Capture happens at the data-link layer and the parser expects **Ethernet**
frames. Traffic a host sends to *itself* (loopback) never crosses the NIC, so a
single machine cannot sniff its own client. Live tests therefore need **two
hosts on the same L2 network** (two machines, or a VM bridged to the host):

- **SERVER** — runs `stealth-udp` with `sudo` on its Ethernet/Wi-Fi interface.
- **CLIENT** — runs `client` / `send_file`, sending to the **server's LAN IP**.

Throughout, replace `<SRV_IP>` with the server's LAN address and `<IFACE>` with
the server's capture interface (find it with `ip link` / `ifconfig`).

---

## Part A — Automated checks (one machine, no root)

- [ ] **A1. Build**

```bash
cargo build --release
```
Expect: builds `target/release/stealth-udp` and `target/release/client`.

- [ ] **A2. Tests, lints, formatting**

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
Expect: all tests pass; clippy and fmt report nothing. These cover the parts
that cannot be observed manually: out-of-order reassembly, FEC recovery of a
lost chunk, compression, integrity-mismatch handling, and the crypto
round-trip / tamper / wrong-key cases.

- [ ] **A3. CLI surface**

```bash
./target/release/stealth-udp --help
./target/release/stealth-udp --version      # prints 1.0.0
./target/release/client                     # prints usage
```

---

## Part B — Server startup & error handling (no traffic needed)

- [ ] **B1. Interface not found → clean error, exit 1**

```bash
./target/release/stealth-udp -i definitely_not_real
echo "exit=$?"
```
Expect: `error: Interface 'definitely_not_real' not found`, `exit=1`.

- [ ] **B2. Missing privileges → clean error (run without sudo)**

```bash
./target/release/stealth-udp -i <IFACE>
```
Expect: a "Failed to open a capture … elevated privileges are required" error
and exit 1 (no panic).

- [ ] **B3. Invalid config → clean error before any capture**

```bash
./target/release/stealth-udp --config /no/such/file.json ; echo "exit=$?"
echo '{ "prot": 1 }' > /tmp/bad.json
./target/release/stealth-udp --config /tmp/bad.json ; echo "exit=$?"
```
Expect: "Cannot read config file …" then "Invalid config file …"; exit 1 both.

- [ ] **B4. Config precedence (CLI overrides file)**

```bash
echo '{ "interface": "cfg_iface", "port": 5555 }' > /tmp/su.json
./target/release/stealth-udp --config /tmp/su.json -p 6666
```
Expect: prints `Listening on port 6666 on interface: cfg_iface` (port from CLI,
interface from file), then a not-found/privilege error for `cfg_iface`.

- [ ] **B5. Invalid `--port` warns and falls back**

```bash
./target/release/stealth-udp -i <IFACE> -p abc
```
Expect: `Invalid port 'abc', falling back to 12345` on stderr.

- [ ] **B6. Ctrl-C is responsive with no traffic**

Start the server with `sudo` (valid interface), send nothing, press Ctrl-C.
Expect: within ~200 ms it prints `Received interrupt signal, shutting down...`
and exits.

- [ ] **B7. Provisioning flag dependencies (no traffic)**

```bash
./target/release/stealth-udp --gen-client alice          # missing --keyring
./target/release/stealth-udp --client-template x         # missing --gen-client/-out
```
Expect: clap errors listing the required missing arguments, exit 2.

---

## Part C — Output formats (live, two hosts)

Start each server variant on SERVER, run the client on CLIENT, then Ctrl-C the
server and inspect the `YYYY-MM-DD-logs/` folder it created.

- [ ] **C1. `raw` (default)**

SERVER: `sudo ./target/release/stealth-udp -i <IFACE> -p 12345`
CLIENT: `printf 'hello raw' | nc -u -w1 <SRV_IP> 12345`
Expect: `…-logs/<CLIENT_IP>.log` contains `hello raw`.

- [ ] **C2. `jsonl`**

SERVER: `sudo ./target/release/stealth-udp -i <IFACE> -p 12345 -f jsonl`
CLIENT: `printf 'hi there' | nc -u -w1 <SRV_IP> 12345`
Expect: `…-logs/<CLIENT_IP>.jsonl` has one JSON line with `timestamp`,
`source`, `length`, `payload_utf8` = `hi there`, and `payload_hex`.

- [ ] **C3. `file` (reassembly)**

SERVER: `sudo ./target/release/stealth-udp -i <IFACE> -p 12345 -f file`
CLIENT:
```bash
head -c 300000 /dev/urandom > /tmp/in.bin
cargo run --release --example send_file -- <SRV_IP>:12345 /tmp/in.bin
```
Expect: `…-logs/<CLIENT_IP>/in.bin` appears; verify it matches:
```bash
# on CLIENT: shasum -a 256 /tmp/in.bin
# on SERVER: shasum -a 256 …-logs/<CLIENT_IP>/in.bin   → same hash
```

---

## Part D — Reassembly options (live, `-f file` on SERVER)

Run each with SERVER in `-f file` mode; compare the received file's SHA-256 to
the source.

- [ ] **D1. Custom chunk size**
CLIENT: `... send_file -- <SRV_IP>:12345 /tmp/in.bin --chunk-size 512`
Expect: identical file received.

- [ ] **D2. Compression**
CLIENT: `... send_file -- <SRV_IP>:12345 /tmp/in.bin --compress`
Expect: identical file received (server decompresses). The client prints
`… , N on the wire` with N ≤ original for compressible input (try a text file).

- [ ] **D3. FEC enabled (XOR and Reed-Solomon)**
CLIENT (XOR): `... send_file -- <SRV_IP>:12345 /tmp/in.bin --fec 8`
CLIENT (RS):  `... send_file -- <SRV_IP>:12345 /tmp/in.bin --fec-rs 10:3`
Expect: identical file received; the client prints `fec-xor/8` or `fec-rs 10:3`.
(Recovery of actually-lost chunks is verified in A2; to force real loss see D6.)

- [ ] **D3b. FEC flags are mutually exclusive (no traffic)**
`... send_file -- host:1 /tmp/in.bin --fec 4 --fec-rs 10:3`
Expect: `error: use either --fec or --fec-rs, not both`, exit 1. Also try
`--fec-rs 10` (missing `:M`) and `--fec-rs 200:100` (`K+M` too large) → clear
errors. `--interleave` without a FEC flag → `error: --interleave requires
--fec or --fec-rs`.

- [ ] **D3c. Interleaving**
CLIENT: `... send_file -- <SRV_IP>:12345 /tmp/in.bin --fec-rs 10:3 --interleave`
Expect: identical file received; the client prints `interleaved`. On a bursty
link (D6) it completes where the non-interleaved run of the same FEC would not.

- [ ] **D4. Passes and repeat**
CLIENT: `... send_file -- <SRV_IP>:12345 /tmp/in.bin --passes 3 --repeat 3`
Expect: identical file received; duplicates are ignored by the server.

- [ ] **D5. Pacing**
CLIENT: `... send_file -- <SRV_IP>:12345 /tmp/in.bin --delay 200`
Expect: identical file received, sent more slowly.

- [ ] **D6. (Advanced, Linux) Force loss to see FEC / incomplete handling**
On SERVER, add loss on the interface, then send with and without FEC:
```bash
sudo tc qdisc add dev <IFACE> root netem loss 5%
# ... run D3 with --fec 4 (should still complete) and without (may not) ...
sudo tc qdisc del dev <IFACE> root netem
```
Expect: with enough FEC the file completes; otherwise the server logs
`Incomplete transfer … missing [...]` on Ctrl-C and keeps a `.part` file.
Reed-Solomon `--fec-rs K:M` tolerates up to M losses per K-chunk block, so it
survives heavier/burstier loss than XOR (one per group) at the same overhead.

- [ ] **D7. Integrity check**
The hash is always sent and verified. A successful transfer implies a matching
hash. (A deliberate mismatch keeping the `.part` is covered in A2.)

- [ ] **D8. Transfer GC**
SERVER: `sudo ./target/release/stealth-udp -i <IFACE> -p 12345 -f file --transfer-timeout 5`
CLIENT: send a large file but interrupt it (Ctrl-C the client mid-transfer).
Expect: after ~5 s idle the server logs `Transfer … timed out …` and keeps the
`.part`.

---

## Part E — Encryption & single-file client (live)

- [ ] **E1. Provision a client (single file)**

SERVER:
```bash
cargo build --release --bin client
./target/release/stealth-udp --gen-client alice --keyring server.keys \
    --client-template target/release/client --client-out client-alice
```
Expect: prints a `Public key: …`, writes `server.keys` and an executable
`client-alice`. Then:
```bash
./client-alice --show-key      # prints the same public key
```

- [ ] **E2. Encrypted transfer end-to-end**

SERVER: `sudo ./target/release/stealth-udp -i <IFACE> -p 12345 -f file --keyring server.keys`
(Expect it to print `Decryption enabled with 1 key(s).`)
CLIENT (copy `client-alice` here): `./client-alice <SRV_IP>:12345 /tmp/in.bin`
Expect: identical file received; the client prints `[encrypted]`.

- [ ] **E3. Wrong / no key is ignored**

With the same encrypted server running, send **plaintext**:
CLIENT: `cargo run --release --example send_file -- <SRV_IP>:12345 /tmp/in.bin`
Expect: nothing is written (undecryptable packets are dropped).

- [ ] **E4. Per-client isolation & revocation**

Provision a second client `bob` (same steps as E1). Both `client-alice` and
`client-bob` transfer successfully. Remove `bob`'s line from `server.keys` and
restart the server: `bob`'s transfers now produce nothing, `alice`'s still work.

- [ ] **E5. Example client with a key argument**

```bash
PUB=$(./client-alice --show-key)
cargo run --release --example send_file -- <SRV_IP>:12345 /tmp/in.bin --server-key $PUB
```
Expect: identical file received (equivalent to the embedded-key client).

---

## Part F — Combined smoke test

A single command exercising many options at once, against an encrypted
`-f file` server:

```bash
./client-alice <SRV_IP>:12345 /tmp/in.bin --compress --fec 8 --passes 2 --repeat 2 --delay 50
```
Expect: identical file received; server folder contains the final file (no
`.part` left behind).

---

## Result checklist

For each transfer the pass criterion is: **the received file's SHA-256 equals
the source's**, and for message/raw modes the log content matches what was sent.
Incomplete or tampered transfers must leave a `.part` (never a final file) and
be logged.
