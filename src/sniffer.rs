//! The capture pipeline: a capture thread reads and parses frames, a writer
//! thread persists them through the sink. Splitting the two means slow disk
//! I/O never blocks packet capture (a bounded channel applies backpressure).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::capture::{self, Capturer};
use crate::parser::{extract_udp_datagram, UdpDatagram};
use crate::sink::DatagramSink;

/// Capacity of the capture -> writer channel. Bounded so a slow disk applies
/// backpressure to the capture thread instead of growing memory without limit.
const CHANNEL_CAPACITY: usize = 1024;

/// Runs the capture pipeline until Ctrl-C is pressed, then flushes the sink.
///
/// `flush_interval` bounds how long buffered data may sit in memory before
/// being written to disk; a zero interval disables periodic flushing (data is
/// still flushed on shutdown).
pub fn run(
    interface: &str,
    port: u16,
    flush_interval: Duration,
    sink: Box<dyn DatagramSink + Send>,
) -> Result<(), String> {
    let capturer = capture::open(interface, port)?;

    let running = Arc::new(AtomicBool::new(true));
    install_signal_handler(running.clone())?;

    let (tx, rx_chan) = mpsc::sync_channel::<UdpDatagram>(CHANNEL_CAPACITY);

    // The writer thread owns the sink and drains the channel.
    let writer = thread::spawn(move || writer_loop(sink, rx_chan, flush_interval));

    // The capture loop runs on this thread and feeds the channel.
    capture_loop(capturer, port, &tx, &running);

    // Closing the channel lets the writer thread finish its final flush.
    drop(tx);
    writer
        .join()
        .map_err(|_| "writer thread panicked".to_string())
}

/// Reads and parses frames until interrupted, forwarding matching datagrams to
/// the writer thread.
fn capture_loop(
    mut capturer: Capturer,
    port: u16,
    tx: &SyncSender<UdpDatagram>,
    running: &AtomicBool,
) {
    while running.load(Ordering::SeqCst) {
        match capturer.next_frame() {
            Ok(Some(frame)) => {
                if let Some(datagram) = extract_udp_datagram(frame, port) {
                    // A send error means the writer thread is gone: stop.
                    if tx.send(datagram).is_err() {
                        break;
                    }
                }
            }
            // A read timeout just means "no packet yet": loop back and
            // re-check the running flag.
            Ok(None) => continue,
            Err(e) => eprintln!("{}", e),
        }
    }
}

/// Consumes datagrams from the channel, persisting each through the sink and
/// flushing periodically. Returns after the channel is closed and a final
/// flush has run.
fn writer_loop(
    mut sink: Box<dyn DatagramSink + Send>,
    rx: Receiver<UdpDatagram>,
    flush_interval: Duration,
) {
    let poll = flush_poll_timeout(flush_interval);
    let mut last_flush = Instant::now();

    loop {
        match rx.recv_timeout(poll) {
            Ok(datagram) => {
                if let Err(e) = sink.handle(&datagram) {
                    eprintln!("Error writing datagram: {}", e);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        if should_flush(last_flush.elapsed(), flush_interval) {
            sink.flush();
            last_flush = Instant::now();
        }
    }

    sink.flush();
}

/// How long the writer waits between channel polls. When periodic flushing is
/// disabled we still poll on a modest interval so shutdown stays responsive.
fn flush_poll_timeout(flush_interval: Duration) -> Duration {
    if flush_interval.is_zero() {
        Duration::from_millis(500)
    } else {
        flush_interval
    }
}

/// Whether enough time has elapsed to warrant a periodic flush. A zero
/// interval disables periodic flushing entirely.
fn should_flush(elapsed: Duration, interval: Duration) -> bool {
    !interval.is_zero() && elapsed >= interval
}

/// Registers a Ctrl-C handler that clears the running flag so both threads can
/// shut down.
fn install_signal_handler(running: Arc<AtomicBool>) -> Result<(), String> {
    ctrlc::set_handler(move || {
        println!("Received interrupt signal, shutting down...");
        running.store(false, Ordering::SeqCst);
    })
    .map_err(|e| format!("Failed to register the signal handler: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    /// A sink that records handled payloads and flush calls for assertions.
    #[derive(Clone, Default)]
    struct Recorder {
        handled: Arc<Mutex<Vec<Vec<u8>>>>,
        flushes: Arc<Mutex<usize>>,
    }

    impl DatagramSink for Recorder {
        fn handle(&mut self, datagram: &UdpDatagram) -> io::Result<()> {
            self.handled.lock().unwrap().push(datagram.payload.clone());
            Ok(())
        }
        fn flush(&mut self) {
            *self.flushes.lock().unwrap() += 1;
        }
    }

    fn datagram(payload: &[u8]) -> UdpDatagram {
        UdpDatagram {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn writer_loop_persists_all_datagrams_then_flushes() {
        let recorder = Recorder::default();
        let (tx, rx) = mpsc::sync_channel::<UdpDatagram>(8);
        tx.send(datagram(b"one")).unwrap();
        tx.send(datagram(b"two")).unwrap();
        drop(tx); // disconnect so the loop terminates

        // Large interval => no periodic flush fires; only the final flush.
        writer_loop(Box::new(recorder.clone()), rx, Duration::from_secs(3600));

        assert_eq!(
            &*recorder.handled.lock().unwrap(),
            &[b"one".to_vec(), b"two".to_vec()]
        );
        assert_eq!(*recorder.flushes.lock().unwrap(), 1);
    }

    #[test]
    fn flush_poll_timeout_uses_default_when_disabled() {
        assert_eq!(
            flush_poll_timeout(Duration::ZERO),
            Duration::from_millis(500)
        );
        assert_eq!(
            flush_poll_timeout(Duration::from_secs(5)),
            Duration::from_secs(5)
        );
    }

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
