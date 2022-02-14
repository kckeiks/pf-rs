mod bpfcode;
mod common;
mod error;
mod generator;
mod lexer;
mod parser;

use pflib_rs;

use generator::Generator;
use lexer::Lexer;
use parser::Parser;
use std::fs;
use std::iter::Peekable;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

use crate::parser::load_filter;
use std::vec::IntoIter;

use pflib_rs::filter::Filter;
use pflib_rs::rule::Builder;

fn main() {
    match Lexer::from_file("program") {
        Ok(lex) => {
            let mut p = Parser::new(lex.collect::<Vec<_>>().into_iter().peekable());
            p.parse_statements();
            let link = load_filter(p.get_rules(), 4);
            // /* keep it alive */
            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();
            ctrlc::set_handler(move || {
                r.store(false, Ordering::SeqCst);
            });

            while running.load(Ordering::SeqCst) {
                eprint!(".");
                thread::sleep(time::Duration::from_secs(1));
            }
        }
        Err(err) => panic!("{}", err),
    }
}
