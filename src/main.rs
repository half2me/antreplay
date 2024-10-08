use clap::Parser;
use flate2::read::GzDecoder;
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use pcap_parser::Block::{EnhancedPacket, InterfaceDescription};
use pcap_parser::{PcapBlockOwned, PcapError, PcapNGReader};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::{thread, time};

/// Replay ANT+ data from a .pcapng file
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the .pcap or gzip compressed .pcap file
    #[arg(long)]
    file: String,

    /// Address to a TCP server to connect to and send the data
    #[arg(long)]
    server: Option<String>,

    /// Optional hello message to send to the TCP server before sending ANT+ messages
    /// a newline character will also be sent after the hello msg
    #[arg(long)]
    hello_msg: Option<String>,
}

fn main() {
    let args = Args::parse();
    let file =
        open_possibly_compressed_file(args.file.as_str()).expect("can't open the specified path");
    let mut reader = PcapNGReader::new(65536, file).unwrap();
    let mut stream = match args.server {
        Some(url) => Some(TcpStream::connect(url).expect("unable to connect to TCP server")),
        None => None,
    };

    if let Some(stream) = &mut stream {
        if let Some(hello) = &args.hello_msg {
            stream
                .write_all(format!("{}\n", hello).as_ref())
                .expect("failed to send hello msg")
        }
    }

    let mut last_timestamp: Option<f64> = None;
    let mut if_tsoffset: Option<u64> = None;
    let mut ts_resolution: Option<u64> = None;
    let mut count: i32 = 0;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(InterfaceDescription(d)) => {
                        if_tsoffset =
                            Some(u64::try_from(d.if_tsoffset).expect("invalid ts offset"));
                        ts_resolution = Some(d.ts_resolution().expect("invalid ts resolution"))
                    }
                    PcapBlockOwned::NG(EnhancedPacket(p)) => {
                        if p.packet_data().len() > 0x40 {
                            // strip USB data from the packet, leaving only ant behind
                            let ant_data = &p.packet_data()[0x40..];

                            // delay by the timestamp diff
                            let ts = p.decode_ts_f64(if_tsoffset.unwrap(), ts_resolution.unwrap());
                            match last_timestamp {
                                None => (),
                                Some(last_ts) => {
                                    let diff = ts - last_ts;
                                    thread::sleep(time::Duration::from_secs_f64(diff))
                                }
                            }
                            last_timestamp = Some(ts);

                            // print to console
                            println!("{:4}. {:02X?}", count, ant_data);

                            if let Some(stream) = &mut stream {
                                stream.write_all(ant_data).expect("unable to send data")
                            }
                        }
                        count += 1;
                    }
                    _ => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
}

/// Read normal or compressed files
pub fn open_possibly_compressed_file(filename: &str) -> Result<Box<dyn Read>, std::io::Error> {
    let path = Path::new(filename);
    let file = File::open(&path)?;

    if path.extension() == Some(OsStr::new("gz")) {
        Ok(Box::new(GzDecoder::new(file)))
    } else {
        Ok(Box::new(file))
    }
}
