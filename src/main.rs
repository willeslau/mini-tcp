mod tcp;

use crate::tcp::state::{Established, SynRecv};
use crate::tcp::{parse_connection_id, ConnectionID};
use anyhow::Result;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use tcp::Connection;

/// Refer to: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
const TCP_PROTOCOL: u8 = 6;
const ETH_HEADER_OFFSET: usize = 0;

fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let mut connections = HashMap::new();
    let nic = tun_tap::Iface::without_packet_info("mini-tcp-tun", tun_tap::Mode::Tun)?;

    loop {
        let mut buf = [0u8; 1500];
        let nbytes = nic.recv(&mut buf)?;

        let (id, ip_header, tcp_header) = match parse_connection_id(&buf) {
            Ok(v) => v,
            Err(e) => {
                log::debug!("not processing due to {:}", e);
                continue;
            }
        };

        log::debug!("received {nbytes:} bytes from id: {id:?}");

        match connections.entry(id.clone()) {
            Entry::Vacant(e) => {
                // there are attacks called SYN flood, modern kernel actually protects against this
                // attack, but we don't really care about this here.
                let handshake = Connection::new(id, ip_header, tcp_header);
                let next = handshake.syn_ack(&nic)?;
                e.insert(ConnectionWrapper::SynRecv(next));
            }
            Entry::Occupied(e) => {
                log::debug!("connection: {id:?} already exists");
                log::info!(
                    "received tcp header, ack: {:}, seq: {:}, syn: {:}",
                    tcp_header.ack(),
                    tcp_header.sequence_number(),
                    tcp_header.syn()
                );
                match e.remove() {
                    ConnectionWrapper::SynRecv(conn) => match conn.check_ack(&nic, &tcp_header) {
                        Ok(conn) => {
                            connections.insert(id, ConnectionWrapper::Established(conn));
                        }
                        Err(e) => {
                            log::error!("error: {e:}");
                        }
                    },
                    _ => {
                        log::error!("invalid state for id: {id:?}");
                    }
                }
                continue;
            }
        }
    }
}

enum ConnectionWrapper {
    SynRecv(Connection<SynRecv>),
    Established(Connection<Established>),
}
