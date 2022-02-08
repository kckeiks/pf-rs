/*
    let filter = Filter::new();
    filter.add_rule(
    RuleBuilder::pass()
    .proto("udp")
    .from("129.4.3.1")
    .to("134.5.2.1")
    );

    builder.action("pass")
    .proto("udp")
    .from("129.4.3.1")
    .to("134.5.2.1")

    RuleBuilder::action("pass")
    .proto("udp")
    .from_any()
    .any_port()
    .to("134.5.2.1")

    Rule::action("pass")
    .proto("udp")?
    .from("129.4.3.1:0")
    .to("1234")
    .new()

    Rule::pass()
    .udp()
    .from_port(["1234", "456"])
    .to(["a")
    .any_port()
    .new()
 */
use serde::{Serialize, Deserialize};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::result::{IntoIter, Iter};
use std::str::FromStr;
use crate::ip::{ToSockAddr, ToIpAddr};

#[derive(Debug, PartialEq)]
enum Action {
    Pass,
    Block
}

#[derive(Debug, PartialEq)]
enum Proto {
    UDP,
    TCP,
}

enum IP {
    V4(u32),
    V6(u128)
}

#[derive(Debug)]
struct Filter {
    rules: Vec<Rule>,
}

#[derive(Default, Debug)]
struct RawRule {
    action: i32,
    saddr4: u32,
    daddr4: u32,
    saddr6: u128,
    daddr6: u128,
    sport: u16,
    dport: u16,
}

#[derive(Debug)]
struct Rule {
    is_ipv6: bool,
    proto: Proto,
    rule: RawRule
}

#[derive(PartialEq, Debug)]
struct Parts {
    action: Action,
    proto: Proto,
    saddr: Option<SocketAddr>,
    daddr: Option<SocketAddr>
}

impl Default for Parts {
    fn default() -> Self {
        Parts {
            action: Action::Block,
            proto: Proto::TCP,
            saddr: None,
            daddr: None,
        }
    }
}

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

    pub fn drop(self) -> Builder {
        self.and_then(move | mut parts| {
            parts.action = Action::Block;
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

    pub fn build(self) -> Result<Rule, ()> {
        self.inner.and_then(| parts | {
            let mut raw_rule = RawRule::default();

            let mut is_ipv6 = false;
            match (&parts.saddr, &parts.daddr) {
                (Some(s), Some(d)) => {
                    if s.is_ipv6() != d.is_ipv6() {
                        return Err(());
                    }
                    is_ipv6 = s.is_ipv6();
                }
                (Some(s), None) => is_ipv6 = s.is_ipv6(),
                (None, Some(d)) => is_ipv6 = d.is_ipv6(),
                (None, None) => is_ipv6 = false,
            }

            if let Some(SocketAddr::V4(a)) = parts.saddr {
                raw_rule.saddr4 = (*a.ip()).into();
                raw_rule.sport = a.port();
            }
            if let Some(SocketAddr::V4(a)) = parts.daddr {
                raw_rule.daddr4 = (*a.ip()).into();
                raw_rule.dport = a.port();
            }
            if let Some(SocketAddr::V6(a)) = parts.saddr {
                raw_rule.saddr6 = (*a.ip()).into();
                raw_rule.sport = a.port();
            }
            if let Some(SocketAddr::V6(a)) = parts.daddr {
                raw_rule.daddr6 = (*a.ip()).into();
                raw_rule.dport = a.port();
            }

            match parts.action {
                Action::Block => raw_rule.action = 0,
                Action::Pass => raw_rule.action = 1,
            }

            Ok(Rule{
                is_ipv6,
                proto: parts.proto,
                rule : raw_rule
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

// TODO: remove this
fn ip_from_str<T: AsRef<str>>(addrs: T) -> Result<IP, AddrParseError> {
    match IpAddr::from_str(addrs.as_ref())? {
        IpAddr::V4(ip) => {
            Ok(IP::V4(ip.into()))
        },
        IpAddr::V6(ip) => {
            Ok(IP::V6(ip.into()))
        }
    }
}