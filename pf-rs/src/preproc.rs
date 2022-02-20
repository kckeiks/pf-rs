use std::collections::{HashMap, VecDeque};
use std::iter::Peekable;
use std::vec::IntoIter;

use anyhow::Result;

use crate::token::Token;
use crate::Lexer;

pub struct PreProc {
    tokens: Vec<Token>,
    buf: Peekable<IntoIter<Token>>,
    idents: HashMap<String, Token>,
}

impl PreProc {
    pub fn new(lex: Lexer) -> Self {
        let mut tokens = lex.collect::<Vec<_>>();
        // \n separate rules so add a nl at the end if needed
        if tokens.last().filter(|&t| matches!(t, Token::Nl)).is_none() {
            tokens.push(Token::Nl);
        }
        PreProc {
            tokens: Vec::new(),
            buf: tokens.into_iter().peekable(),
            idents: HashMap::new(),
        }
    }

    fn process_list(&mut self, line: Vec<Token>, tokens: Vec<Vec<Token>>) -> Result<()> {
        let mut buf: VecDeque<VecDeque<Token>> = cartesian_product(tokens);

        while let Some(mut token_vec) = buf.pop_front() {
            for token in line.iter() {
                if let Token::List(_) = token {
                    // replace List token with the next token from cartesian product result set
                    self.tokens.push(
                        token_vec
                            .pop_front()
                            .expect("error: failed to process list token"),
                    )
                } else {
                    self.tokens.push(token.clone());
                }
            }
        }
        Ok(())
    }

    fn process_line(&mut self, raw_line: Vec<Token>) -> Result<()> {
        let mut buf: Vec<Vec<Token>> = Vec::new();

        let mut line = self.process_macros(raw_line)?;

        for token in line.iter() {
            if let Token::List(token_vec) = token {
                buf.push(token_vec.clone())
            }
        }

        if !buf.is_empty() {
            self.process_list(line, buf)?;
        } else {
            self.tokens.append(&mut line);
        }
        Ok(())
    }

    fn process_macros(&mut self, line: Vec<Token>) -> Result<Vec<Token>> {
        let mut res = Vec::new();

        let mut tokens = line.into_iter().peekable();

        while let Some(t) = tokens.next() {
            if let Token::Ident(name) = t {
                let msg = format!("unknown identifier {}", name.as_str());
                let val = self.idents.get(name.as_str()).expect(msg.as_str());
                res.push(val.clone());
            } else if let Token::Def(name) = t {
                tokens
                    .next()
                    .filter(|t| matches!(t, Token::Assign))
                    .expect("expected `=` in macro declaration"); // this will never panic

                let msg = format!("invalid `{} = [no value]`", name.as_str());
                let token = tokens.next().expect(msg.as_str());
                self.idents.insert(name, token);
            } else {
                res.push(t);
            }
        }

        Ok(res)
    }

    pub fn preprocess(mut self) -> Result<Vec<Token>> {
        // skip initial new lines if any
        while let Some(Token::Nl) = self.buf.peek() {
            self.buf.next();
        }

        let mut buf: Vec<Token> = Vec::new();
        loop {
            let token = self.buf.next();

            if let Some(Token::Nl) = token {
                self.process_line(buf)?;
                buf = Vec::new();
                continue;
            }

            match token {
                Some(t) => buf.push(t),
                None => break,
            }
        }

        Ok(self.tokens)
    }
}

fn cartesian_product(set: Vec<Vec<Token>>) -> VecDeque<VecDeque<Token>> {
    let res_len = set.iter().fold(1, |l, e| l * e.len());
    let mut res: VecDeque<VecDeque<Token>> = VecDeque::new();
    res.resize_with(res_len, || VecDeque::new());

    for tokens in set.into_iter() {
        let mut i = 0;
        let mut tmp = tokens.iter();
        while i < res.len() {
            match tmp.next() {
                Some(val) => {
                    res[i].push_back(val.clone());
                    i += 1;
                }
                None => tmp = tokens.iter(),
            }
        }
    }
    res
}
