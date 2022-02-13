use crate::common::*;
use std::fs;
use std::iter::Peekable;
use std::vec::IntoIter;
use crate::common::Token::{Port, To};

pub struct Lexer {
    buf: Peekable<IntoIter<char>>,
}

impl Lexer {
    pub fn from_str(str: &str) -> Lexer {
        Lexer {
            buf: str.chars().collect::<Vec<_>>().into_iter().peekable(),
        }
    }

    pub fn from_file(file_path: &str) -> Result<Self, String> {
        Ok(Self::from_str(
            &fs::read_to_string(file_path).expect("could not read file"),
        ))
    }

    fn skip_whitespace(&mut self) {
        loop {
            match self.buf.peek() {
                Some(c) if c.is_ascii_whitespace() => {
                    self.buf.next();
                }
                _ => {
                    break;
                }
            }
        }
    }

    fn next_word(&mut self) -> String {
        // skip white space first
        self.skip_whitespace();

        let mut s = String::new();
        loop {
            match self.buf.peek() {
                Some(c) if !c.is_ascii_whitespace() => {
                    s.push(*c);
                    self.buf.next();
                }
                _ => break,
            }
        }
        s
    }
}

impl Iterator for Lexer {
    type Item = Token;

    fn next(&mut self) -> Option<Self::Item> {
        let word = self.next_word();
        if word.is_empty() {
            return None;
        }
        match &word[..] {
            PASS => Some(Token::Pass),
            BLOCK => Some(Token::Block),
            ON => Some(Token::On(self.next_word())),
            PROTO => Some(Token::Proto(self.next_word())),
            PORT => Some(Token::Port(self.next_word())),
            FROM => Some(Token::From(self.next_word())),
            TO => Some(Token::To(self.next_word())),
            NEWLINE => Some(Token::NewLine(word)),
            _ => None,
        }
    }
}
