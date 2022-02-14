use bincode2;
use ctrlc;
use http::request;
use std::fmt::Alignment::Right;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};
use tempfile::tempdir;

mod bpf;
mod bpfcode;
mod compile;
mod error;
pub mod filter;
mod ip;
pub mod rule;

use crate::rule::Builder;
pub use bpf::BPFLink;

pub fn load_filter(ifindex: i32) {
    let addrs = [
        ("10.11.4.2", "10.11.3.2"),
        ("10.11.6.2", "10.11.3.2"),
        ("10.11.5.2", "10.11.2.2"),
        ("10.11.127.2", "100.11.2.2"),
        ("0:0:0:0:0:FFFF:204.152.189.116", "1:0:0:0:0:0:0:8"),
        ("0:0:0:0:0:FFFF:204.152.189.116", "1:0:0:0:0:0:0:8"),
    ];

    let mut filter = filter::Filter::new();

    for (src, dst) in addrs.into_iter() {
        filter.add_rule(
            Builder::new()
                .block()
                .from_addr(src)
                .to_addr(dst)
                .build()
                .expect("this faileddd"),
        );
    }
    filter.load_on(ifindex);
}
