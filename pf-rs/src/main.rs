use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

use anyhow::Context;
use clap::Parser as ClapParser;

use lexer::Lexer;

use crate::parser::Parser;
use crate::preproc::PreProc;

mod common;
mod error;
mod lexer;
mod parser;
mod preproc;

#[derive(ClapParser)]
#[clap(name = "pf")]
#[clap(author = "Fausto Miguel Guarniz <mi9uel9@gmail.com>")]
#[clap(version = "0.1.0")]
#[clap(about = "eBPF-based packet filter for Rust", long_about = None)]
struct Cli {
    /// index of device where filter should be attached to
    ifindex: i32,

    /// path to config file
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: Option<PathBuf>,

    #[clap(short)]
    /// Only generate .c and .o files for filter
    generate: bool,
}

fn main() {
    let cli = Cli::parse();

    let mut config = PathBuf::from_str("/etc/pfrs/pfrs.conf").unwrap();
    if let Some(path) = cli.config.as_deref() {
        config = PathBuf::from(path);
    }

    let l = Lexer::from_file(config.as_path().to_str().unwrap()).unwrap();

    let mut p = PreProc::new(l);
    let tokens = p
        .preprocess()
        .expect("preprocessing failed")
        .into_iter()
        .peekable();

    let mut p = Parser::new(tokens);
    p.parse_statements().expect("parsing failed");

    if cli.generate {
        parser::generate_filter(p.get_rules()).expect("generating filter failed");
        return;
    }

    let res = parser::load_filter(p.get_rules(), cli.ifindex);
    match res {
        Ok(_) => println!("pf-rs: filter is attached"),
        Err(e) => panic!("{}", e.to_string()),
    }

    // /* keep it alive */
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    while running.load(Ordering::SeqCst) {
        eprint!(".");
        thread::sleep(time::Duration::from_secs(1));
    }
}
