use std::iter::Peekable;
use std::vec::IntoIter;

use anyhow::{bail, Result};

use libpf_rs::rule::{Builder, Rule};

use crate::token::Token;

pub struct Parser {
    tokens: Peekable<IntoIter<Token>>,
    rules: Vec<Rule>,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Parser {
            tokens: tokens.into_iter().peekable(),
            rules: Vec::new(),
        }
    }

    fn peek_then_read<P>(&mut self, p: P) -> Option<Token>
    where
        P: FnOnce(&Token) -> bool,
    {
        if let Some(token) = self.tokens.peek() {
            if p(token) {
                return Some(self.tokens.next().unwrap());
            }
        }
        None
    }

    fn read_or_die<P>(&mut self, p: P, msg: &str) -> Token
    where
        P: FnOnce(&Token) -> bool,
    {
        match self.peek_then_read(p) {
            Some(t) => t,
            None => panic!("{}", msg),
        }
    }

    fn read_arg(&mut self) -> Option<String> {
        match self.tokens.next()? {
            Token::Val(s) => Some(s),
            _ => None,
        }
    }

    fn parse_statement(&mut self) -> Result<()> {
        let mut builder = Builder::new();

        if self.peek_then_read(|t| matches!(t, Token::Pass)).is_some() {
            builder = builder.pass();
        } else if self.peek_then_read(|t| matches!(t, Token::Block)).is_some() {
            builder = builder.block();
        } else {
            bail!("expected `pass` or `block` token");
        }

        // self.read_or_die(|t| matches!(t, Token::Proto), "expected token `proto`");
        // builder = builder.proto(self.read_arg().expect("expected protocol after `proto`"));

        self.read_or_die(|t| matches!(t, Token::From), "expected token `from`");
        builder = builder.from_addr(
            self.read_arg()
                .expect("expected src IP after `to`")
                .as_str(),
        );

        if self.peek_then_read(|t| matches!(t, Token::Port)).is_some() {
            let port = self.read_arg().expect("missing src port after `port`");
            builder = builder.from_port(port.parse::<u16>()?);
        }

        self.read_or_die(|t| matches!(t, Token::To), "expected token `to`");
        builder = builder.to_addr(
            self.read_arg()
                .expect("expected dst IP after `to`")
                .as_str(),
        );

        if self.peek_then_read(|t| matches!(t, Token::Port)).is_some() {
            let port = self.read_arg().expect("missing dst port after `port`");
            builder = builder.to_port(port.parse::<u16>()?);
        }

        self.rules.push(builder.build()?);
        Ok(())
    }

    pub fn parse_statements(mut self) -> Result<Vec<Rule>> {
        loop {
            if self.tokens.peek().is_none() {
                break;
            }
            self.parse_statement()?;
        }
        Ok(self.rules)
    }
}
