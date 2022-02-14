use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

use lexer::Lexer;
use parser::Parser;

use crate::parser::load_filter;

mod common;
mod error;
mod lexer;
mod parser;

fn main() {
    match Lexer::from_file("program") {
        Ok(lex) => {
            let mut p = Parser::new(lex.collect::<Vec<_>>().into_iter().peekable());
            if let Err(e) = p.parse_statements() {
                panic!("{}", e.to_string());
            }

            let _ = load_filter(p.get_rules(), 4);
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
