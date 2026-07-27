//! Entry point: resolve configuration, prepare the log directory and run the
//! capture loop. All real logic lives in the library modules.

use std::fs::create_dir_all;

use chrono::Local;

use stealth_udp::{capture, cli, sink, sniffer};

fn main() {
    let args = cli::parse();

    let interface = args.interface.unwrap_or_else(capture::default_interface);

    let today = Local::now().format("%Y-%m-%d");
    let logs_dir = format!("{}-logs", today);
    create_dir_all(&logs_dir).expect("Error creating the log folder");

    println!(
        "Listening on port {} on interface: {}",
        args.port, interface
    );

    let sink = sink::build_sink(args.format, logs_dir);
    sniffer::run(&interface, args.port, sink);
}
