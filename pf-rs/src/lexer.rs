use std::fs;
use std::iter::Peekable;
use std::vec::IntoIter;

use anyhow::Result;

use crate::token::Token;
use crate::token::{
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

    fn read_def(&mut self) -> Token {
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

            let item = self.read_while(|c| !c.is_ascii_whitespace() && c != CLOSE_CBRACK);
            if let Some(i) = item {
                items.push(Token::Val(i));
            }
        }

        if items.is_empty() {
            panic!("error: no tokens inside list")
        }

        Token::List(items)
    }

    fn interpret(&mut self, word: String) -> Token {
        // there could be nl after this, we don't know what token word is
        self.read_while(|c| c.is_ascii_whitespace() && c != NL);

        if self.buf.peek().filter(|&&c| c == ASSIGN).is_some() {
            return Token::Def(word);
        }
        Token::Val(word)
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
    fn read_while<P>(&mut self, p: P) -> Option<String>
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

    // only use if you're absolutely sure that there should not be any ws including a \n
    fn consume_whitespace(&mut self) {
        self.read_while(|c| c.is_ascii_whitespace());
    }

    fn read_next(&mut self) -> Option<String> {
        self.read_while(|c| !c.is_ascii_whitespace())
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
        self.read_while(|c| c.is_ascii_whitespace() && c != NL);

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
            return Some(self.read_def());
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
            _ => Some(self.interpret(s)),
        }
    }
}
