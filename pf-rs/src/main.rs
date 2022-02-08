mod bpfcode;
mod common;
mod generator;
mod lexer;
mod parser;

use bpfpf_lib;

use generator::Generator;
use lexer::Lexer;
use parser::Parser;
use std::fs;
use std::iter::Peekable;
use std::vec::IntoIter;

fn main() {
    // match Lexer::from_file("program") {
    //     Ok(lex) => {
    //         let mut p = Parser::new(lex.collect::<Vec<_>>().into_iter().peekable());
    //         // p.parse_statements();
    //         let mut gen = Generator::new(p);
    //         gen.generate_program();
    //     }
    //     Err(err) => panic!("{}", err),
    // }
    bpfpf_lib::load_filter();
}
