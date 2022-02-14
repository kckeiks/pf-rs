use anyhow::{bail, Result};
use std::iter::Peekable;
use std::vec::IntoIter;

use crate::common::*; // TODO: fix
use crate::error::Error;
use crate::lexer::Lexer;
use pflib_rs::filter::Filter;
use pflib_rs::rule::{Builder, Rule};
use pflib_rs::BPFLink;

pub struct Parser {
    tokens: Peekable<IntoIter<Token>>,
    rules: Vec<Rule>,
}

impl Parser {
    pub fn new(tokens: Peekable<IntoIter<Token>>) -> Self {
        Parser {
            tokens,
            rules: Vec::new(),
        }
    }

    fn parse_statement(&mut self) -> Result<()> {
        let mut builder = Builder::new();
        match self.tokens.peek() {
            Some(Token::Pass) => {
                builder = builder.pass();
            }
            Some(Token::Block) => {
                builder = builder.block();
            }
            Some(t) => bail!(Error::ParseError(format!(
                "Expected `pass` or `block`, instead got {:?}",
                t
            ))),
            None => bail!(Error::ParseError("Expected `pass` or `block`".to_string())),
        }
        self.tokens.next();

        if let Some(Token::Proto(proto)) = self.tokens.peek() {
            builder = builder.proto(proto);
            self.tokens.next();
        }

        // Use IPaddress to validate that it is valid
        match self.tokens.peek() {
            Some(Token::From(src)) => {
                builder = builder.from_addr(src.as_str());
            }
            Some(t) => bail!(Error::ParseError(format!(
                "expecting `from`, instead got {:?}",
                t
            ))),
            None => bail!(Error::ParseError(
                "expecting `from` - read useage".to_string()
            )),
        };
        self.tokens.next();

        // remove duplicate
        if let Some(Token::Port(p)) = self.tokens.peek() {
            builder = builder.from_port(
                p.parse::<u16>()
                    .map_err(|e| Error::ParseError(e.to_string()))?,
            );
            self.tokens.next();
        }

        match self.tokens.peek() {
            Some(Token::To(dst)) => {
                builder = builder.to_addr(dst.as_str());
            }
            Some(t) => bail!(Error::ParseError(format!(
                "expecting `to`, instead got {:?}",
                t
            ))),
            None => bail!(Error::ParseError(
                "expecting `to` - read useage".to_string()
            )),
        };
        self.tokens.next();

        if let Some(Token::Port(p)) = self.tokens.peek() {
            builder = builder.to_port(
                p.parse::<u16>()
                    .map_err(|e| Error::ParseError(e.to_string()))?,
            );
            self.tokens.next();
        }

        self.rules.push(
            builder
                .build()
                .map_err(|e| Error::ParseError(e.to_string()))?,
        );
        Ok(())
    }

    pub fn parse_statements(&mut self) {
        loop {
            if self.tokens.peek().is_none() {
                break;
            }
            self.parse_statement();
        }
    }

    pub fn get_rules(self) -> Vec<Rule> {
        self.rules
    }
}

pub fn load_filter(rules: Vec<Rule>, ifindex: i32) -> Result<BPFLink> {
    let mut f = Filter::new();
    for r in rules.into_iter() {
        f.add_rule(r);
    }
    let mut link = f.load_on(ifindex)?;
    Ok(link)
}
