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
    // // pflib_rs::load_filter();
    // let addrs = [
    //     ("10.11.4.2", "10.11.3.2"),
    //     ("10.11.6.2", "10.11.3.2"),
    //     ("10.11.5.2", "10.11.2.2"),
    //     ("10.11.127.2", "100.11.2.2"),
    //     ("0:0:0:0:0:FFFF:204.152.189.116", "1:0:0:0:0:0:0:8"),
    //     ("0:0:0:0:0:FFFF:204.152.189.116", "1:0:0:0:0:0:0:8"),
    // ];
    //
    // let mut filter = Filter::new();
    //
    // for (src, dst) in addrs.into_iter() {
    //     filter.add_rule(
    //         Builder::new()
    //             .block()
    //             .from_addr(src)
    //             .to_addr(dst)
    //             .build()
    //             .expect("this faileddd"),
    //     );
    // }
    // filter.load_on(4);
}
