use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::result::{IntoIter, Iter};
use std::str::FromStr;
use crate::ip::{ToSockAddr, ToIpAddr};
use serde::{Serialize, Deserialize};

#[derive(Debug)]
pub(crate) enum Proto {
    UDP,
    TCP,
    Any,
}

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Block = 1,
    Pass = 2
}


#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug, Default)]
pub(crate) struct RawRule {
    action: u32,
    quick: u32,
    proto: u32,
    sport: u16,
    dport: u16,
    saddr4: u32,
    daddr4: u32,
    saddr6: u128,
    daddr6: u128,
}

#[derive(Debug)]
pub(crate) enum InnerRule {
    DefaultRule(Action),
    IPv4Rule(RawRule),
    IPv6Rule(RawRule),
}

#[derive(Debug)]
pub struct Rule {
    inner: InnerRule
}

impl Rule {
    // TODO: need at least rust 1.18
    pub(crate) fn read_rule(self) -> InnerRule {
        self.inner
    }
}

#[derive(Debug)]
struct Parts {
    action: Action,
    quick: bool,
    proto: Proto,
    saddr: Option<SocketAddr>,
    daddr: Option<SocketAddr>
}

impl Default for Parts {
    fn default() -> Self {
        Parts {
            action: Action::Pass,
            quick: false,
            proto: Proto::Any,
            saddr: None,
            daddr: None,
        }
    }
}

#[derive(Debug)]
pub struct Builder {
    inner: Result<Parts, ()>
}

impl Builder {
    pub fn new() -> Self {
        Builder { inner: Ok(Parts::default()) }
    }

    pub fn pass(self) -> Builder {
        self.and_then(move | mut parts| {
            parts.action = Action::Pass;
            Ok(parts)
        })
    }

    pub fn block(self) -> Builder {
        self.and_then(move | mut parts| {
            parts.action = Action::Block;
            Ok(parts)
        })
    }

    pub fn quick(self) -> Builder {
        self.and_then(| mut parts | {
            parts.quick = true;
            Ok(parts)
        })
    }

    pub fn proto<T: AsRef<str>>(self, proto: T) -> Builder {
        self.and_then(|mut parts| {
            parts.proto = match proto.as_ref().to_lowercase().as_str() {
                "udp" => Proto::UDP,
                "tcp" => Proto::TCP,
                _ => return Err(())
            };
            Ok(parts)
        })
    }

    pub fn from<T: ToSockAddr>(self, src: T) -> Builder {
        self.and_then(move |mut parts| {
            let addr = match src.to_sock_addr() {
                Ok(a) => a,
                Err(_) => return Err(()),  // TODO: handle better
            };
            parts.saddr = Some(addr);
            Ok(parts)
        })
    }

    pub fn from_any_port<T: ToIpAddr>(self, src: T) -> Builder {
        self.and_then(move |mut parts| {
            let ip_addr = match src.to_ip_addr() {
                Ok(a) => a,
                Err(_) => return Err(()) // TODO: handle better
            };
            let addr = SocketAddr::new(ip_addr, 0);
            parts.saddr = Some(addr);
            Ok(parts)
        })
    }

    pub fn to<T: ToSockAddr>(self, dst: T) -> Builder {
        self.and_then(move |mut parts| {
            let addr = match dst.to_sock_addr() {
                Ok(a) => a,
                Err(_) => return Err(()), // TODO: handle better
            };
            parts.daddr = Some(addr);
            Ok(parts)
        })
    }

    pub fn to_any_port<T: ToIpAddr>(self, dst: T) -> Builder {
        self.and_then(move |mut parts| {
            let ip_addr = match dst.to_ip_addr() {
                Ok(a) => a,
                Err(_) => return Err(()) // TODO: handle better
            };
            let sock_addr = SocketAddr::new(ip_addr, 0);
            parts.daddr = Some(sock_addr);
            Ok(parts)
        })
    }


    pub fn pass_all(self) -> Result<Rule, ()> {
        self.inner.and_then(| _ | {
            Ok(Rule {
                inner: InnerRule::DefaultRule(Action::Pass)
            })
        })
    }

    pub fn block_all(self) -> Result<Rule, ()> {
        self.inner.and_then(| _ | {
            Ok(Rule {
                inner: InnerRule::DefaultRule(Action::Block)
            })
        })
    }

    pub fn build(self) -> Result<Rule, ()> {
        self.inner.and_then(| parts | {
            let mut raw_rule = RawRule::default();

            let mut is_ipv6 = false;

            match (&parts.saddr, &parts.daddr) {
                (Some(s), Some(d)) => {
                    // if we have src and dst then they should be of the same ip version
                    if s.is_ipv6() != d.is_ipv6() {
                        return Err(());
                    }
                    is_ipv6 = s.is_ipv6();
                }
                (Some(s), None) => is_ipv6 = s.is_ipv6(),
                (None, Some(d)) => is_ipv6 = d.is_ipv6(),
                (None, None) => return Err(()), // TODO: not allowed, direct them to use pass/block all
            }

            if let Some(SocketAddr::V4(a)) = parts.saddr {
                let addr: u32 = (*a.ip()).into();
                raw_rule.saddr4 = addr.to_be();
                raw_rule.sport = a.port().to_be();
            }
            if let Some(SocketAddr::V4(a)) = parts.daddr {
                let addr: u32 = (*a.ip()).into();
                raw_rule.daddr4 = addr.to_be();
                raw_rule.dport = a.port().to_be();
            }
            if let Some(SocketAddr::V6(a)) = parts.saddr {
                let addr: u128 = (*a.ip()).into();
                raw_rule.saddr6 = addr.to_be();
                raw_rule.sport = a.port().to_be();
            }
            if let Some(SocketAddr::V6(a)) = parts.daddr {
                let addr: u128 = (*a.ip()).into();
                raw_rule.daddr6 =  addr.to_be();
                raw_rule.dport = a.port().to_be();
            }

            match parts.action {
                Action::Block => raw_rule.action = 1,
                Action::Pass => raw_rule.action = 2,
            }

            raw_rule.quick = match parts.quick {
                false => 0,
                true => 1,
            };

            raw_rule.proto = match &parts.proto {
                Proto::TCP => 6,
                Proto::UDP => 17,
                Proto::Any => 0,
            };

            let inner_rule = if is_ipv6 {
                InnerRule::IPv6Rule(raw_rule)
            } else {
                InnerRule::IPv4Rule(raw_rule)
            };

            Ok(Rule {
                inner: inner_rule
            })
        })
    }

    fn and_then<F>(self, op: F) -> Self
        where F: FnOnce(Parts) -> Result<Parts, ()> {
        Builder {
            inner: self.inner.and_then(op)
        }
    }

}
