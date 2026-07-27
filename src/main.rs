//! Entry point: dispatch the requested invocation. All real logic lives in the
//! library modules.

use std::fs::create_dir_all;

use chrono::Local;

use stealth_udp::cli::{Args, Invocation};
use stealth_udp::{capture, cli, crypto, embed, keyring, sink, sniffer};

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn try_main() -> Result<(), String> {
    match cli::parse()? {
        Invocation::GenClient {
            name,
            keyring_path,
            client_template,
            client_out,
        } => gen_client(&name, &keyring_path, client_template, client_out),
        Invocation::Run(args) => run_sniffer(args),
    }
}

/// Generates a client key pair, stores its private key in the keyring, and
/// either prints the public key or bakes it into a provisioned client binary.
fn gen_client(
    name: &str,
    keyring_path: &str,
    client_template: Option<String>,
    client_out: Option<String>,
) -> Result<(), String> {
    let keypair = crypto::generate_keypair();
    keyring::append(keyring_path, name, &keypair.private)?;
    println!(
        "Client '{}' created. Its private key was added to {}.",
        name, keyring_path
    );

    println!("Public key: {}", crypto::to_hex(&keypair.public));

    if let (Some(template), Some(out)) = (client_template, client_out) {
        provision_client(&template, &out, &keypair.public)?;
        println!("Provisioned single-file client written to {}.", out);
    }
    Ok(())
}

/// Patches a copy of the client template with `public_key` and writes it to
/// `out` as an executable.
fn provision_client(template: &str, out: &str, public_key: &[u8; 32]) -> Result<(), String> {
    let mut binary = std::fs::read(template)
        .map_err(|e| format!("cannot read client template '{}': {}", template, e))?;
    embed::patch(&mut binary, public_key)?;
    std::fs::write(out, &binary).map_err(|e| format!("cannot write '{}': {}", out, e))?;
    make_executable(out)?;
    resign(out)
}

/// Patching invalidates a binary's code signature; on macOS (mandatory on
/// Apple Silicon) an ad-hoc re-sign is required or the OS kills it on launch.
#[cfg(target_os = "macos")]
fn resign(path: &str) -> Result<(), String> {
    let status = std::process::Command::new("codesign")
        .args(["--force", "--sign", "-", path])
        .status()
        .map_err(|e| format!("failed to run codesign (required on macOS): {}", e))?;
    if !status.success() {
        return Err(format!(
            "codesign failed for '{}'; ad-hoc sign it with: codesign --force --sign - {}",
            path, path
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn resign(_path: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat '{}': {}", path, e))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).map_err(|e| format!("cannot chmod '{}': {}", path, e))
}

#[cfg(not(unix))]
fn make_executable(_path: &str) -> Result<(), String> {
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

    let mut sink = sink::build_sink(args.format, logs_dir, args.transfer_timeout);
    if !args.keyring.is_empty() {
        println!("Decryption enabled with {} key(s).", args.keyring.len());
        sink = Box::new(sink::DecryptingSink::new(args.keyring, sink));
    }

    sniffer::run(&interface, args.port, args.flush_interval, sink)
}
