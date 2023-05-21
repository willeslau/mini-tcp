use crate::tcp::{ReceiveSequenceSpace, SendSequenceSpace};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

/// The initial listen state for a tcp connection
pub struct Listen<'a> {
    pub(crate) ip_header: Ipv4HeaderSlice<'a>,
    pub(crate) tcp_header: TcpHeaderSlice<'a>,
}

#[derive(PartialEq, Eq, Debug)]
#[repr(C)]
pub struct SynRecv {
    pub(crate) snd: SendSequenceSpace,
    pub(crate) rcv: ReceiveSequenceSpace,
}

#[derive(PartialEq, Eq, Debug)]
#[repr(C)]
pub struct Established {
    pub(crate) snd: SendSequenceSpace,
    pub(crate) rcv: ReceiveSequenceSpace,
}

#[cfg(test)]
mod tests {
    use crate::tcp::state::{Established, SynRecv};
    use crate::tcp::{ReceiveSequenceSpace, SendSequenceSpace};

    #[test]
    fn test_transmute() {
        let sr = SynRecv {
            snd: SendSequenceSpace {
                up: true,
                wnd: 10,
                una: 20,
                nxt: 30,
                wl1: 40,
                wl2: 50,
                iss: 60,
            },
            rcv: ReceiveSequenceSpace {
                up: true,
                wnd: 70,
                nxt: 80,
                irs: 90,
            },
        };

        let tr = unsafe { std::mem::transmute::<SynRecv, Established>(sr) };

        assert_eq!(tr.snd.up, true);
        assert_eq!(tr.snd.wnd, 10);
        assert_eq!(tr.snd.una, 20);
        assert_eq!(tr.snd.nxt, 30);
        assert_eq!(tr.snd.wl1, 40);
        assert_eq!(tr.snd.wl2, 50);
        assert_eq!(tr.snd.iss, 60);
    }
}
