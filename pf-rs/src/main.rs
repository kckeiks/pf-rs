use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

use anyhow::{anyhow, Result};
use clap::Parser as ClapParser;

use lexer::Lexer;
use libpf_rs::filter::Filter;
use libpf_rs::rule::Rule;
use libpf_rs::BPFLink;

use crate::parser::Parser;
use crate::preproc::PreProc;

mod lexer;
mod parser;
mod preproc;
mod token;

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

    let pre_proc = PreProc::new(l);
    let tokens = pre_proc.preprocess().unwrap();

    let parser = Parser::new(tokens);
    let rules = parser.parse_statements().unwrap();

    if cli.generate {
        generate_filter(rules).unwrap();
        return;
    }

    let res = load_filter(rules, cli.ifindex);
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

pub fn load_filter(rules: Vec<Rule>, ifindex: i32) -> Result<BPFLink> {
    let mut f = Filter::new();
    for r in rules.into_iter() {
        f.add_rule(r);
    }
    Ok(f.load_on(ifindex)?)
}

pub fn generate_filter(rules: Vec<Rule>) -> Result<()> {
    let mut f = Filter::new();
    for r in rules.into_iter() {
        f.add_rule(r);
    }
    f.generate_src().map_err(|e| anyhow!(e))
}
