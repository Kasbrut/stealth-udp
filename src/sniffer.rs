//! The capture loop: wires capture, parsing and a sink together and shuts
//! down cleanly on an interrupt signal.

use std::io::ErrorKind;
use std::sync::mpsc;

use crate::capture;
use crate::parser::extract_udp_datagram;
use crate::sink::DatagramSink;

/// Runs the capture loop until Ctrl-C is pressed, then flushes the sink.
pub fn run(interface: &str, port: u16, mut sink: Box<dyn DatagramSink>) {
    let (signal_tx, signal_rx) = mpsc::channel::<()>();
    install_signal_handler(signal_tx);

    let mut rx = capture::open_channel(interface);

    loop {
        if signal_rx.try_recv().is_ok() {
            println!("Received interrupt signal, performing final flush...");
            sink.flush();
            break;
        }

        match rx.next() {
            Ok(frame) => {
                if let Some(datagram) = extract_udp_datagram(frame, port) {
                    if let Err(e) = sink.handle(&datagram) {
                        eprintln!("Error writing datagram: {}", e);
                    }
                }
            }
            // A timed-out or would-block read just means "no packet yet": loop
            // back and re-check the interrupt signal.
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => continue,
            Err(e) => eprintln!("Error reading packet: {}", e),
        }
    }
}

/// Registers a Ctrl-C handler that notifies the capture loop to shut down.
fn install_signal_handler(signal_tx: mpsc::Sender<()>) {
    ctrlc::set_handler(move || {
        // If the receiver is already gone, shutdown is under way: ignore.
        let _ = signal_tx.send(());
    })
    .expect("Failed to register the signal handler");
}
