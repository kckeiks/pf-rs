use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{thread, time};
use std::fmt::Alignment::Right;
use std::path::Path;
use ctrlc;
use tempfile::tempdir;
use bincode2;
use http::request;

mod bpf;
mod compile;
mod error;
mod filter;
mod ip;
mod bpfcode;
mod rule;

pub fn load_filter() {

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
            rule::Builder::new()
            .block()
            .from_any_port(src)
            .to_any_port(dst)
            .build().unwrap()
        );
    }
    filter.load_on(4);
}