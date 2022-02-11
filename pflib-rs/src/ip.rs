use std::net::{AddrParseError, IpAddr, SocketAddr};
use std::str::FromStr;

pub trait ToSockAddr {
    fn to_sock_addr(&self) -> Result<SocketAddr, AddrParseError>;
}

pub trait ToIpAddr {
    fn to_ip_addr(&self) -> Result<IpAddr, AddrParseError>;
}

impl ToIpAddr for &str {
    fn to_ip_addr(&self) -> Result<IpAddr, AddrParseError> {
        IpAddr::from_str(self)
    }
}

impl ToIpAddr for IpAddr {
    fn to_ip_addr(&self) -> Result<IpAddr, AddrParseError> {
        Ok(*self)
    }
}

impl ToSockAddr for &str {
    fn to_sock_addr(&self) -> Result<SocketAddr, AddrParseError> {
        SocketAddr::from_str(self)
    }
}

impl ToSockAddr for SocketAddr {
    fn to_sock_addr(&self) -> Result<SocketAddr, AddrParseError> {
        Ok(*self)
    }
}