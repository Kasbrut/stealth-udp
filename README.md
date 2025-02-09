
# Stealth-UDP

`stealth-udp` allows you to create a rudimentary UDP server capable of sniffing packets on a specific network interface, even if protected by a firewall.

Collect all sent data in a subfolder named 'YYYY-MM-DD-logs' in separate files based on the client's IP address.

**Disclosure:**  
I must clarify that I am not an experienced Rust developer. Please review my code before running it, and feel free to suggest any modifications or improvements.

## Building the Source Code

```bash
cargo build --release
```

## Viewing Available Options

```bash
./stealth-udp --help
```

## Running the Server with Administrator Permissions

```bash
sudo ./stealth-udp [OPTIONS]
```

## Example of Sending Data

```bash
cat ~/Desktop/test-file.txt | pv | nc -u <IP-ADDRESS> <PORT>
```
