use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

pub trait ToSockAddr {
    fn to_sock_addr(&self) -> Result<SocketAddr, AddrParseError>;
}

impl ToSockAddr for &str {
    fn to_sock_addr(&self) -> Result<SocketAddr, AddrParseError> {
        SocketAddr::from_str(self).or_else(|_| Ok(SocketAddr::new(IpAddr::from_str(self)?, 0)))
    }
}

impl ToSockAddr for IpAddr {
    fn to_sock_addr(&self) -> Result<SocketAddr, AddrParseError> {
        Ok(SocketAddr::new(*self, 0))
    }
}

impl ToSockAddr for SocketAddr {
    fn to_sock_addr(&self) -> Result<SocketAddr, AddrParseError> {
        Ok(*self)
    }
}

pub fn get_zero_addr(ipv6: bool) -> SocketAddr {
    // These functions should not fail
    let ip_addr = if ipv6 {
        IpAddr::V6(Ipv6Addr::from_str("::").unwrap())
    } else {
        IpAddr::V4(Ipv4Addr::from_str("0.0.0.0").unwrap())
    };
    SocketAddr::new(ip_addr, 0)
}
