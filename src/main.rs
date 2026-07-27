//! Entry point: dispatch the requested invocation. All real logic lives in the
//! library modules.

use std::fs::create_dir_all;

use chrono::Local;

use stealth_udp::cli::{Args, Invocation};
use stealth_udp::{capture, cli, crypto, keyring, sink, sniffer};

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn try_main() -> Result<(), String> {
    match cli::parse()? {
        Invocation::GenClient { name, keyring_path } => gen_client(&name, &keyring_path),
        Invocation::Run(args) => run_sniffer(args),
    }
}

/// Generates a client key pair, stores its private key in the keyring and
/// prints the public key to hand to that client.
fn gen_client(name: &str, keyring_path: &str) -> Result<(), String> {
    let keypair = crypto::generate_keypair();
    keyring::append(keyring_path, name, &keypair.private)?;
    println!(
        "Client '{}' created. Its private key was added to {}.",
        name, keyring_path
    );
    println!("Give this public key to the client:");
    println!("{}", crypto::to_hex(&keypair.public));
    Ok(())
}

/// Prepares the log directory and runs the capture pipeline.
fn run_sniffer(args: Args) -> Result<(), String> {
    let interface = match args.interface {
        Some(iface) => iface,
        None => capture::default_interface()?,
    };

    let today = Local::now().format("%Y-%m-%d");
    let logs_dir = format!("{}-logs", today);
    create_dir_all(&logs_dir)
        .map_err(|e| format!("Error creating the log folder '{}': {}", logs_dir, e))?;

    println!(
        "Listening on port {} on interface: {}",
        args.port, interface
    );

    let mut sink = sink::build_sink(args.format, logs_dir);
    if !args.keyring.is_empty() {
        println!("Decryption enabled with {} key(s).", args.keyring.len());
        sink = Box::new(sink::DecryptingSink::new(args.keyring, sink));
    }

    sniffer::run(&interface, args.port, args.flush_interval, sink)
}
