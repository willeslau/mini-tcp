use crate::{ETH_HEADER_OFFSET, TCP_PROTOCOL};
use anyhow::anyhow;
use anyhow::Result;
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::net::Ipv4Addr;

pub mod handshake;
pub mod state;

pub const DEFAULT_WINDOW_SIZE: u16 = 64240;

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub struct ConnectionID {
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_addr: Ipv4Addr,
    pub dst_port: u16,
}

pub fn parse_connection_id(data: &[u8]) -> Result<(ConnectionID, Ipv4HeaderSlice, TcpHeaderSlice)> {
    let ipv4_header = Ipv4HeaderSlice::from_slice(&data[ETH_HEADER_OFFSET..])?;
    let ip_proto = ipv4_header.protocol();
    if ip_proto != TCP_PROTOCOL {
        return Err(anyhow!("not tcp protocol, skip"));
    }

    let tcp_header_idx = ETH_HEADER_OFFSET + ipv4_header.slice().len();
    let tcp_header = TcpHeaderSlice::from_slice(&data[tcp_header_idx..])?;

    let id = ConnectionID {
        src_addr: ipv4_header.source_addr(),
        src_port: tcp_header.source_port(),
        dst_addr: ipv4_header.destination_addr(),
        dst_port: tcp_header.destination_port(),
    };

    Ok((id, ipv4_header, tcp_header))
}

/// Send Sequence Variables
///
/// SND.UNA - send unacknowledged
/// SND.NXT - send next
/// SND.WND - send window
/// SND.UP  - send urgent pointer
/// SND.WL1 - segment sequence number used for last window update
/// SND.WL2 - segment acknowledgment number used for last window update
/// ISS     - initial send sequence number
///
/// 1         2          3          4
/// ----------|----------|----------|----------
///         SND.UNA    SND.NXT    SND.UNA
///                              +SND.WND
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
#[derive(PartialEq, Eq, Debug)]
#[repr(C)]
pub struct SendSequenceSpace {
    pub up: bool,
    pub wnd: u16,
    pub una: u32,
    pub nxt: u32,
    pub wl1: u32,
    pub wl2: u32,
    pub iss: u32,
}

/// 1          2          3
/// ----------|----------|----------
///        RCV.NXT    RCV.NXT
///                  +RCV.WND
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
#[derive(PartialEq, Eq, Debug)]
#[repr(C)]
pub struct ReceiveSequenceSpace {
    pub up: bool,
    pub wnd: u16,
    pub nxt: u32,
    pub irs: u32,
}

pub struct Connection<T> {
    id: ConnectionID,
    state: T,
}

impl<T> Connection<T> {
    pub fn from(id: ConnectionID, state: T) -> Self {
        Self { id, state }
    }
}

/// Checks the receiving data, i.e. the tcp header + the data received are valid.
/// See https://www.ietf.org/rfc/rfc793.txt page 24.
///
/// When data is received the following comparisons are needed:
///     RCV.NXT = next sequence number expected on an incoming segments, and is the left or lower edge of the receive window
///     RCV.NXT+RCV.WND-1 = last sequence number expected on an incoming segment, and is the right or upper edge of the receive window
///     SEG.SEQ = first sequence number occupied by the incoming segment
///     SEG.SEQ+SEG.LEN-1 = last sequence number occupied by the incoming segment
///
/// Due to zero windows and zero length segments, we have four cases for the acceptability of an incoming segment:
///
///     Segment Receive  Test
///     Length  Window
///     ------- -------  -------------------------------------------
///        0       0     SEG.SEQ = RCV.NXT
///        0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
///       >0       0     not acceptable
///       >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
///                      or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
///
/// A segment is judged to occupy a portion of valid receive sequence space if
///     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
/// or
///     RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
/// Note that the above is a *OR* condition.
pub(crate) fn is_recv_data_in_window(
    rcv: &ReceiveSequenceSpace,
    seg: &TcpHeaderSlice,
    data: Option<&[u8]>,
) -> bool {
    // Case 1:
    if data.is_none() && rcv.wnd == 0 && seg.sequence_number() == rcv.nxt {
        return true;
    }

    // Case 3:
    if data.is_some() && rcv.wnd == 0 {
        return false;
    }

    // Checking Case 2 and part of Case 4
    let wnd_edge = rcv.nxt.wrapping_add(rcv.wnd as u32);

    // wrapping check: RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    if is_wrapping_lte_ls(rcv.nxt, seg.sequence_number(), wnd_edge) {
        return true;
    }

    // Case 4:
    if data.is_some() && rcv.wnd > 0 {
        // wrapping check: RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        let mut seg_len = data.map(|s| s.len() as u32).unwrap_or(0);

        // SEG.LEN = the number of octets occupied by the data in the segment (counting SYN and FIN)
        // https://www.ietf.org/rfc/rfc793.txt, page 24
        if seg.syn() {
            seg_len += 1;
        }
        if seg.fin() {
            seg_len += 1;
        }

        let seg_last_seq = seg.sequence_number().wrapping_add(seg_len).wrapping_sub(1);

        return is_wrapping_lte_ls(rcv.nxt, seg_last_seq, wnd_edge);
    }

    false
}

/// Checks if the three numbers a, b, c are: a <= b < c with wrapping
fn is_wrapping_lte_ls<N: PartialOrd>(a: N, b: N, c: N) -> bool {
    // case 1:  >>>> a >>>> b >>>> c
    if a <= b && b < c {
        return true;
    }

    // case 2:  >>>> c >>>> a >>>> b
    if c < a && a <= b {
        return true;
    }

    // case 3:  >>>> b >>>> c >>>> a
    if b < c && c < a {
        return true;
    }

    false
}

/// Checks the ack number is actually within the send window. This also considers the case of usigned int wrapping.
pub(crate) fn is_ack_in_window(snd: &SendSequenceSpace, ack: u32) -> bool {
    // SND.UNA < SEG.ACK =< SND.NXT

    // case 1:   >>>> una >>>> ack >>>> nxt
    if snd.una < ack && ack <= snd.nxt {
        return true;
    }

    // case 2:   >>>> nxt >>>> una >>>> ack
    if snd.nxt < snd.una && snd.una < ack {
        return true;
    }

    // case 3:   >>>> ack >>>> nxt >>>> una
    if ack <= snd.una && snd.nxt < snd.una {
        return true;
    }

    false
}
