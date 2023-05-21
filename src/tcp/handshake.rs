//! This implements the basic 3 way handshake process to establish a tcp connection.
//! The basic 3-Way handshake for connection synchronization is as follows:
//!
//!       TCP A                                                TCP B
//!
//!   1.  CLOSED                                               LISTEN
//!
//!   2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED
//!
//!   3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED
//!
//!   4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED
//!
//!   Other payload sent...

use crate::tcp::state::{Established, Listen, SynRecv};
use crate::tcp::{
    is_ack_in_window, is_recv_data_in_window, ReceiveSequenceSpace, SendSequenceSpace,
    DEFAULT_WINDOW_SIZE,
};
use crate::{Connection, ConnectionID, TCP_PROTOCOL};
use anyhow::{anyhow, Result};
use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

/// Implements the initial SYN response handling
///        TCP A                                                TCP B
///
///   1.  CLOSED                                               LISTEN
///
///   2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED
///
///   3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED
impl<'a> Connection<Listen<'a>> {
    pub fn new(
        id: ConnectionID,
        ip_header: Ipv4HeaderSlice<'a>,
        tcp_header: TcpHeaderSlice<'a>,
    ) -> Self {
        Self::from(
            id,
            Listen {
                ip_header,
                tcp_header,
            },
        )
    }

    /// Generates the next to be used by subsequent steps. See https://www.ietf.org/rfc/rfc793.txt page 64
    /// for the full description.
    fn next_state(&self, iss: u32, wnd: u16) -> SynRecv {
        SynRecv {
            // SND.NXT is set to ISS+1 and SND.UNA to ISS
            snd: SendSequenceSpace {
                una: iss,
                nxt: iss.wrapping_add(1),
                wnd,
                up: false,
                wl1: 0,
                wl2: 0,
                iss,
            },
            // Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ and any other
            // control or text should be queued for processing later.
            rcv: ReceiveSequenceSpace {
                nxt: self.state.tcp_header.sequence_number().wrapping_add(1),
                wnd: self.state.tcp_header.window_size(),
                up: false,
                irs: self.state.tcp_header.sequence_number(),
            },
        }
    }

    /// Performs checks on establish a connection, refer to https://www.ietf.org/rfc/rfc793.txt page 64
    /// for the full pseudocode.
    fn preflight_checks(&self) -> Result<()> {
        if self.state.tcp_header.ack() {
            // Any acknowledgment is bad if it arrives on a connection still in
            // the LISTEN state.  An acceptable reset segment should be formed
            // for any arriving ACK-bearing segment.  The RST should be
            // formatted as follows:
            //     <SEQ=SEG.ACK><CTL=RST>
            return Err(anyhow!("ack should not be set, invalid payload"));
        }
        if !self.state.tcp_header.syn() {
            // If the SYN bit is set, check the security.  If the
            // security/compartment on the incoming segment does not exactly
            // match the security/compartment in the TCB then send a reset and
            // return.
            //     <SEQ=SEG.ACK><CTL=RST>
            return Err(anyhow!("syn should be set, invalid payload"));
        }

        // TODO:
        // If the SEG.PRC is greater than the TCB.PRC then if allowed by
        // the user and the system set TCB.PRC<-SEG.PRC, if not allowed
        // send a reset and return.
        //     <SEQ=SEG.ACK><CTL=RST>
        Ok(())
    }

    pub fn syn_ack(self, nic: &tun_tap::Iface) -> Result<Connection<SynRecv>> {
        self.preflight_checks()?;

        // TODO: replace seq_number with random
        let initial_seq_num = 0;
        let window_size = DEFAULT_WINDOW_SIZE;
        let next_state = self.next_state(initial_seq_num, window_size);

        // ISS should be selected and a SYN segment sent of the form:
        //     <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
        let mut reply_tcp_header = TcpHeader::new(
            self.id.dst_port,
            self.id.src_port,
            initial_seq_num,
            window_size,
        );
        reply_tcp_header.acknowledgment_number = next_state.rcv.nxt;
        reply_tcp_header.syn = true;
        reply_tcp_header.ack = true;
        // this field is needed, if no checksum, the other host will not respond with ACK.
        reply_tcp_header.checksum =
            reply_tcp_header.calc_checksum_ipv4(&self.state.ip_header.to_header(), &[])?;

        let reply_ip_header = Ipv4Header::new(
            reply_tcp_header.header_len(),
            64,
            TCP_PROTOCOL,
            self.id.dst_addr.octets(),
            self.id.src_addr.octets(),
        );

        // TODO: maybe there are better ways instead of init vec?
        let mut response = vec![];
        reply_ip_header.write(&mut response)?;
        reply_tcp_header.write(&mut response)?;

        nic.send(&response)?;

        let Connection { id, .. } = self;
        Ok(Connection::from(id, next_state))
    }
}

/// Implements the reciving of ACK after Syn Recv
///   4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED
impl Connection<SynRecv> {
    pub fn check_ack(
        self,
        _nic: &tun_tap::Iface,
        tcp_header: &TcpHeaderSlice,
    ) -> Result<Connection<Established>> {
        if !tcp_header.ack() {
            return Err(anyhow!("no ack received"));
        }

        if !is_ack_in_window(&self.state.snd, tcp_header.acknowledgment_number()) {
            return Err(anyhow!("not valid ack for syn recv"));
        }

        if !is_recv_data_in_window(&self.state.rcv, tcp_header, None) {
            return Err(anyhow!("not valid ack for syn recv"));
        }

        let Connection { id, state } = self;
        let next_state = unsafe { std::mem::transmute::<SynRecv, Established>(state) };

        Ok(Connection::from(id, next_state))
    }
}
