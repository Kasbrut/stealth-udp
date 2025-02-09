extern crate pnet;

use chrono::Local;
use clap::{Arg, Command};
use ctrlc;
use pnet::datalink;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn main() {
    let (interface, port, logs_dir) = setup();

    let file_map: Arc<Mutex<HashMap<String, BufWriter<File>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let (tx, rx_signal) = mpsc::channel::<()>();

    setup_signal_handler(tx.clone());

    let mut rx = open_channel(&interface);

    packet_sniffer_loop(&mut *rx, port, &logs_dir, &file_map, rx_signal);
}

fn setup() -> (String, u16, String) {
    let matches = Command::new("UDP Packet Sniffer")
        .version("1.0")
        .about("UDP Packet Sniffer")
        .arg(
            Arg::new("iface")
                .short('i')
                .long("iface")
                .value_name("INTERFACE")
                .help("Specify the network interface"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .default_value("12345")
                .help("Specify the network port"),
        )
        .get_matches();

    let port: u16 = matches
        .get_one::<String>("port")
        .unwrap()
        .parse()
        .unwrap_or(12345);

    let interface_name = matches.get_one::<String>("iface");

    let interface = match interface_name {
        Some(name) => name.clone(),
        None => select_default_interface(),
    };

    let today = Local::now().format("%Y-%m-%d").to_string();
    let logs_dir = format!("{}-logs", today);

    create_dir_all(&logs_dir).expect("Error creating the log folder");

    println!("Listening on port {} on interface: {}", port, interface);

    (interface, port, logs_dir)
}

fn select_default_interface() -> String {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback())
        .expect("No active network interface found")
        .name
}

fn setup_signal_handler(tx: mpsc::Sender<()>) {
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Failed to register the signal handler");
}

fn open_channel(interface_name: &str) -> Box<dyn datalink::DataLinkReceiver> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Interface not found");

    match datalink::channel(&interface, Default::default())
        .expect("Failed to obtain the communication channel")
    {
        datalink::Channel::Ethernet(_, rx) => rx,
        _ => panic!("Unsupported communication channel"),
    }
}

fn packet_sniffer_loop(
    rx: &mut dyn datalink::DataLinkReceiver,
    port: u16,
    logs_dir: &str,
    file_map: &Arc<Mutex<HashMap<String, BufWriter<File>>>>,
    rx_signal: mpsc::Receiver<()>,
) {
    loop {
        if let Ok(_) = rx_signal.try_recv() {
            println!("Received interrupt signal, performing final flush...");
            flush_all_buffers(file_map);
            break;
        }

        match rx.next() {
            Ok(packet) => process_packet(packet, port, logs_dir, file_map),
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn process_packet(
    packet: &[u8],
    port: u16,
    logs_dir: &str,
    file_map: &Arc<Mutex<HashMap<String, BufWriter<File>>>>,
) {
    if let Some(eth_packet) = EthernetPacket::new(packet) {
        if let Some(ipv4_packet) = Ipv4Packet::new(eth_packet.payload()) {
            if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                if udp_packet.get_destination() == port {
                    let src_ip = ipv4_packet.get_source().to_string().replace(".", "_");
                    let udp_payload = udp_packet.payload();

                    let mut file_map_lock = file_map.lock().unwrap();
                    let file = file_map_lock.entry(src_ip.clone()).or_insert_with(|| {
                        let file_path = format!("{}/{}.log", logs_dir, src_ip);
                        let file = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(file_path)
                            .expect("Failed to open the file for the IP");
                        BufWriter::new(file)
                    });

                    if let Err(e) = file.write_all(udp_payload) {
                        eprintln!("Error writing to file: {}", e);
                    }
                }
            }
        }
    }
}

fn flush_all_buffers(file_map: &Arc<Mutex<HashMap<String, BufWriter<File>>>>) {
    let mut file_map_lock = file_map.lock().unwrap();
    for (ip_key, file) in file_map_lock.iter_mut() {
        if let Err(e) = file.flush() {
            eprintln!("Error flushing the file {}: {}", ip_key, e);
        }
    }
}
