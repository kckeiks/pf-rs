use std::collections::VecDeque;
use std::iter::Peekable;
use std::vec::IntoIter;

use anyhow::Result;

use crate::common::Token;
use crate::Lexer;

pub struct PreProc {
    tokens: Vec<Token>,
    buf: Peekable<IntoIter<Token>>,
}

impl PreProc {
    pub fn new(lex: Lexer) -> Self {
        PreProc {
            tokens: Vec::new(),
            buf: lex.collect::<Vec<_>>().into_iter().peekable(),
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

    fn process_line(&mut self, mut line: Vec<Token>) -> Result<()> {
        let mut buf: Vec<Vec<Token>> = Vec::new();

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

    pub fn preprocess(mut self) -> Result<Vec<Token>> {
        // skip initial new lines if any
        while let Some(Token::Nl) = self.buf.peek() {
            self.buf.next();
        }

        let mut buf: Vec<Token> = Vec::new();
        loop {
            let token = self.buf.next();

            if let Some(Token::Nl) = token {
                self.process_line(buf);
                buf = Vec::new();
                continue;
            }

            match token {
                Some(t) => buf.push(t),
                None => break,
            }
        }

        for t in self.tokens.iter() {
            println!("{:?}", t);
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
