use crate::common::*;
use std::fs;
use std::iter::Peekable;
use std::vec::IntoIter;

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
            PASS => Some(Token::Pass(word)),
            BLOCK => Some(Token::Block(word)),
            ON => Some(Token::On(self.next_word())),
            PROTO => Some(Token::Proto(self.next_word())),
            FROM => Some(Token::From(self.next_word())),
            TO => Some(Token::To(self.next_word())),
            NEWLINE => Some(Token::NewLine(word)),
            w if w.ends_with(ASSIGN_PATTERN) => Some(Token::Assign(word)),
            w if w.starts_with(IDEN_PATTERN) => Some(Token::Identifier(word)),
            w if !w.is_empty() => Some(Token::Value(word)),
            _ => None,
        }
    }
}
