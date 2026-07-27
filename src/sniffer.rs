//! The capture loop: wires capture, parsing and a sink together, flushes
//! buffered data periodically, and shuts down cleanly on an interrupt signal.

use std::io::ErrorKind;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::capture;
use crate::parser::extract_udp_datagram;
use crate::sink::DatagramSink;

/// Runs the capture loop until Ctrl-C is pressed, then flushes the sink.
///
/// `flush_interval` bounds how long buffered data may sit in memory before
/// being written to disk; a zero interval disables periodic flushing (data is
/// still flushed on shutdown).
pub fn run(
    interface: &str,
    port: u16,
    flush_interval: Duration,
    mut sink: Box<dyn DatagramSink>,
) -> Result<(), String> {
    let (signal_tx, signal_rx) = mpsc::channel::<()>();
    install_signal_handler(signal_tx);

    let mut rx = capture::open_channel(interface)?;
    let mut last_flush = Instant::now();

    loop {
        if signal_rx.try_recv().is_ok() {
            println!("Received interrupt signal, performing final flush...");
            sink.flush();
            break;
        }

        if should_flush(last_flush.elapsed(), flush_interval) {
            sink.flush();
            last_flush = Instant::now();
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
            // back and re-check the interrupt signal and flush timer.
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => continue,
            Err(e) => eprintln!("Error reading packet: {}", e),
        }
    }

    Ok(())
}

/// Whether enough time has elapsed to warrant a periodic flush. A zero
/// interval disables periodic flushing entirely.
fn should_flush(elapsed: Duration, interval: Duration) -> bool {
    !interval.is_zero() && elapsed >= interval
}

/// Registers a Ctrl-C handler that notifies the capture loop to shut down.
fn install_signal_handler(signal_tx: mpsc::Sender<()>) {
    ctrlc::set_handler(move || {
        // If the receiver is already gone, shutdown is under way: ignore.
        let _ = signal_tx.send(());
    })
    .expect("Failed to register the signal handler");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_flush_before_interval() {
        assert!(!should_flush(
            Duration::from_secs(2),
            Duration::from_secs(5)
        ));
    }

    #[test]
    fn flushes_at_or_after_interval() {
        assert!(should_flush(Duration::from_secs(5), Duration::from_secs(5)));
        assert!(should_flush(Duration::from_secs(9), Duration::from_secs(5)));
    }

    #[test]
    fn zero_interval_disables_periodic_flush() {
        assert!(!should_flush(Duration::from_secs(100), Duration::ZERO));
    }
}
