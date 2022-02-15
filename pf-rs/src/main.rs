use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

use clap::Parser as ClapParser;

use lexer::Lexer;
use parser::Parser;

use crate::parser::load_filter;

mod common;
mod error;
mod lexer;
mod parser;

#[derive(ClapParser)]
#[clap(name = "rpf")]
#[clap(author = "Fausto Miguel Guarniz <mi9uel9@gmail.com>")]
#[clap(version = "0.1.0")]
#[clap(about = "eBPF-based packet filter for Rust", long_about = None)]
struct Cli {
    /// index of device where filter should be attached to
    ifindex: i32,

    /// path to config file
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    let mut config = PathBuf::from_str("/etc/pfrs/pfrs.conf").expect("Some error");
    if let Some(path) = cli.config.as_deref() {
        config = PathBuf::from(path);
    }

    match Lexer::from_file(config.as_path().to_str().unwrap()) {
        Ok(lex) => {
            let mut p = Parser::new(lex.collect::<Vec<_>>().into_iter().peekable());
            if let Err(e) = p.parse_statements() {
                panic!("{}", e.to_string());
            }

            let _ = load_filter(p.get_rules(), cli.ifindex);
            // /* keep it alive */
            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();

            if let Err(e) = ctrlc::set_handler(move || {
                r.store(false, Ordering::SeqCst);
            }) {
                panic!("{}", e.to_string());
            }

            while running.load(Ordering::SeqCst) {
                eprint!(".");
                thread::sleep(time::Duration::from_secs(1));
            }
        }
        Err(err) => panic!("{}", err),
    }
}
