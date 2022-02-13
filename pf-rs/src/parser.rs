use std::iter::Peekable;
use std::vec::IntoIter;
use anyhow::{bail, Result};

use crate::common::*;
use crate::lexer::Lexer;
use crate::error::Error;

pub struct Parser {
    tokens: Peekable<IntoIter<Token>>,
    rules: Vec<IntoIter<Token>>,
}

impl Parser {
    pub fn new(tokens: Peekable<IntoIter<Token>>) -> Self {
        Parser {
            tokens,
            rules: Vec::new()
        }
    }

    fn parse_statement(&mut self) -> Result<()> {
        let mut rule: Vec<Token> = Vec::new();
        match self.tokens.peek() {
            Some(Token::Pass) | Some(Token::Block)=> rule.push(self.tokens.next().unwrap()),
            Some(t) => bail!(Error::ParseError("invalid token {:?}", t)),
            None => bail!(Error::ParseError("Expected `pass` or `block`".to_string())),
        }

        match self.tokens.peek() {
            Some(Token::Proto(proto)) => rule.push(self.tokens.next().unwrap()),
            Some(_) => (),
            None => bail!(Error::ParseError("missing required keywords - read useage".to_string())),
        }

        // Use IPaddress to validate that it is valid
        match self.tokens.peek() {
            Some(Token::From(_)) => rule.push(self.tokens.next().unwrap()),
            Some(t) => bail!("invalid token {:?}, expected `from`", t),
            None => bail!(Error::ParseError("missing required keywords - read useage".to_string())),
        }

        // remove duplicate
        match self.tokens.peek() {
            Some(Token::Port(_)) => rule.push(self.tokens.next().unwrap()),
            Some(_) => (),
            None => (),
        }

        match self.tokens.peek() {
            Some(Token::To(_)) => rule.push(self.tokens.next().unwrap()),
            Some(t) => bail!("invalid token {:?}, expected `to`", t),
            None => bail!(Error::ParseError("missing required keywords - read useage".to_string())),
        }

        match self.tokens.peek() {
            Some(Token::Port(_)) => rule.push(self.tokens.next().unwrap()),
            Some(_) => (),
            None => (),
        }
        self.rules.push(rule.into_iter());
        Ok(())
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
