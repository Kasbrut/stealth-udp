//! Entry point: resolve configuration, prepare the log directory and run the
//! capture loop. All real logic lives in the library modules.

use std::fs::create_dir_all;

use chrono::Local;

use stealth_udp::{capture, cli, sink, sniffer};

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn try_main() -> Result<(), String> {
    let args = cli::parse();

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

    let sink = sink::build_sink(args.format, logs_dir);
    sniffer::run(&interface, args.port, args.flush_interval, sink)
}
