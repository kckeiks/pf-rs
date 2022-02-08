use std::iter::Peekable;
use std::vec::IntoIter;

use crate::common::*;
use crate::lexer::Lexer;

pub struct Parser {
    tokens: Peekable<IntoIter<Token>>,
    ifaces: Vec<String>,
    src_allow_list: Vec<String>,
    src_block_list: Vec<String>,
    dst_allow_list: Vec<String>,
    dst_block_list: Vec<String>,
    protos: Vec<String>,
}

impl Parser {
    pub fn new(tokens: Peekable<IntoIter<Token>>) -> Self {
        Parser {
            tokens,
            ifaces: Vec::new(),
            src_allow_list: Vec::new(),
            src_block_list: Vec::new(),
            dst_allow_list: Vec::new(),
            dst_block_list: Vec::new(),
            protos: Vec::new(),
        }
    }

    fn parse_statement(&mut self) {
        match self.tokens.next() {
            Some(Token::Pass(action)) | Some(Token::Block(action)) => {
                println!("action {:?}", action);
                // TODO: handle/fix these ifs
                if self.tokens.peek().is_none() {
                    panic!("you must tell us what to {:?}", &action);
                }
                match self.tokens.next() {
                    Some(Token::On(iface)) => {
                        println!("on {:?}", iface);
                        self.ifaces.push(iface);
                    }
                    _ => {
                        panic!("missing iface");
                    }
                }
                match self.tokens.next() {
                    Some(Token::Proto(proto)) => {
                        println!("proto {:?}", proto);
                        self.protos.push(proto);
                    }
                    _ => {}
                }

                match self.tokens.next() {
                    Some(Token::From(ip)) => {
                        println!("from {:?}", ip);
                        if action == "pass" {
                            self.src_allow_list.push(ip);
                        } else {
                            self.src_block_list.push(ip);
                        }
                    }
                    _ => {
                        panic!("missing from src addrress");
                    }
                }

                match self.tokens.next() {
                    Some(Token::To(ip)) => {
                        println!("to {:?}", ip);
                        if action == "pass" {
                            self.dst_allow_list.push(ip);
                        } else {
                            self.dst_block_list.push(ip);
                        }
                    }
                    _ => {
                        panic!("missing to dst address");
                    }
                }
            }
            _ => {
                panic!("expected action: pass or block");
            }
        }
    }

    pub fn parse_statements(&mut self) {
        loop {
            if let Some(Token::NewLine(_)) = self.tokens.peek() {
                break;
            }
            self.parse_statement();
        }
    }
}
