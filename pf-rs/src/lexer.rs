use std::fs;
use std::iter::Peekable;
use std::vec::IntoIter;

use anyhow::Result;

use crate::common::Token;
use crate::common::{
    ALL, ASSIGN, BLOCK, CLOSE_CBRACK, FROM, NL, ON, OPEN_CBRACK, PASS, PORT, PROTO, REPLACE_PREFIX,
    TO,
};

pub struct Lexer {
    buf: Peekable<IntoIter<char>>,
}

impl Lexer {
    pub fn from_str(str: String) -> Lexer {
        Lexer {
            buf: str.chars().collect::<Vec<_>>().into_iter().peekable(),
        }
    }

    pub fn from_file(file_path: &str) -> Result<Self> {
        Ok(Self::from_str(
            fs::read_to_string(file_path)
                .expect("could not read file")
                .trim_start_matches(|c: char| c.is_ascii_whitespace())
                .to_string(),
        ))
    }

    fn read_ident(&mut self) -> Token {
        self.consume_whitespace();
        let ident = self.read_next().expect("invalid token `$`");
        Token::Ident(ident)
    }

    fn read_list_items(&mut self) -> Token {
        let mut items: Vec<Token> = Vec::new();

        loop {
            if let Some(c) = self.peek_then_read(|c| c == CLOSE_CBRACK || c == NL) {
                if c == NL {
                    panic!(r#"unexpected token `\n` in list"#)
                }
                break;
            }

            self.consume_whitespace();

            let item = self.lex_map_while(|c| !c.is_ascii_whitespace() && c != CLOSE_CBRACK);
            if let Some(i) = item {
                items.push(Token::Expr(i));
            }
        }

        if items.is_empty() {
            panic!("error: no tokens inside list")
        }

        Token::List(items)
    }

    fn peek_then_read<P>(&mut self, p: P) -> Option<char>
    where
        P: FnOnce(char) -> bool,
    {
        if let Some(&c) = self.buf.peek() {
            if p(c) {
                return Some(self.buf.next().unwrap());
            }
        }
        None
    }

    // this one peeks and does not consume if there is no match unlink iter.map_while
    fn lex_map_while<P>(&mut self, p: P) -> Option<String>
    where
        P: Fn(char) -> bool,
    {
        let mut s = String::new();
        while let Some(c) = self.buf.peek() {
            if p(*c) {
                s.push(*c);
                self.buf.next();
            } else {
                break;
            }
        }

        if s.is_empty() {
            return None;
        }

        Some(s)
    }

    fn consume_whitespace(&mut self) {
        self.lex_map_while(|c| c.is_ascii_whitespace());
    }

    fn read_next(&mut self) -> Option<String> {
        self.lex_map_while(|c| !c.is_ascii_whitespace())
    }

    fn read_newline(&mut self) -> Token {
        self.consume_whitespace();
        Token::Nl
    }
}

impl Iterator for Lexer {
    type Item = Token;

    fn next(&mut self) -> Option<Self::Item> {
        // skip whitespace except new line char
        self.lex_map_while(|c| c.is_ascii_whitespace() && c != NL);

        if self.peek_then_read(|c| c == ASSIGN).is_some() {
            return Some(Token::Assign);
        }
        if self.peek_then_read(|c| c == NL).is_some() {
            return Some(self.read_newline());
        }
        if self.peek_then_read(|c| c == OPEN_CBRACK).is_some() {
            return Some(self.read_list_items());
        }
        if self.peek_then_read(|c| c == REPLACE_PREFIX).is_some() {
            return Some(self.read_ident());
        }

        let s = match self.read_next() {
            Some(w) => w,
            None => return None,
        };

        match &s[..] {
            ALL => Some(Token::All),
            PASS => Some(Token::Pass),
            BLOCK => Some(Token::Block),
            ON => Some(Token::On),
            PROTO => Some(Token::Proto),
            PORT => Some(Token::Port),
            FROM => Some(Token::From),
            TO => Some(Token::To),
            exp => Some(Token::Expr(exp.to_string())),
        }
    }
}
