//! stealth-udp: a rudimentary UDP sniffer that captures datagrams at the
//! data-link layer and stores each client's payload in per-IP files.
//!
//! The crate is split into small, single-responsibility modules so the core
//! logic (packet parsing, formatting, file writing) can be unit tested without
//! root privileges or a live network interface.

pub mod capture;
pub mod cli;
pub mod parser;
pub mod sink;
pub mod sniffer;
pub mod writer;
