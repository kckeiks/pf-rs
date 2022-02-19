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

    fn read_ident(&mut self) -> Token {
        self.consume_whitespace();
        let ident = self.read_next().expect("invalid token `$`");
        Token::Ident(ident)
    }

    fn read_list_items(&mut self) -> Token {
        let mut items: Vec<Token> = Vec::new();

        // consume `{` if there is one
        // unit tests include open curly brace
        if let Some(c) = self.buf.peek() {
            if *c == OPEN_CBRACK {
                self.buf.next();
            }
        }

        loop {
            self.read_while(|c| c.is_ascii_whitespace() && c != NL);

            if self.peek_then_read(|c| c == NL).is_some() {
                panic!(r#"unexpected token `\n` in list"#)
            }

            if self.peek_then_read(|c| c == CLOSE_CBRACK).is_some() {
                break;
            }

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
            _ => Some(self.interpret(s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Lexer;
    use super::Token::{Assign, Block, Def, From, Ident, List, Nl, Pass, Proto, To, Val};

    macro_rules! test_lexer {
        ($name:ident, $input:expr, $expect:expr) => {
            #[test]
            fn $name() {
                let rule = String::from($input);
                let lex = Lexer::from_str(rule.clone());
                assert_eq!(
                    lex.into_iter().collect::<Vec<_>>(),
                    $expect,
                    "input was `{}`",
                    rule
                )
            }
        };
    }

    macro_rules! test_list {
        ($name:ident, $input:expr, $expect:expr) => {
            #[test]
            fn $name() {
                let rule = String::from($input);
                let mut lex = Lexer::from_str(rule.clone());
                assert_eq!(lex.read_list_items(), $expect, "input was `{}`", rule)
            }
        };
        ($name:ident, $input:expr) => {
            #[test]
            #[should_panic]
            fn $name() {
                let rule = String::from($input);
                let mut lex = Lexer::from_str(rule.clone());
                lex.read_list_items();
            }
        };
    }

    macro_rules! test_next {
        ($name:ident, $input:expr, $expect:expr) => {
            #[test]
            fn $name() {
                let input = String::from($input);
                let mut lex = Lexer::from_str(input.clone());
                assert_eq!(lex.next(), Some($expect), "input was `{}`", input);
            }
        };
        ($name:ident, $input:expr) => {
            #[test]
            #[should_panic]
            fn $name() {
                let input = String::from($input);
                let mut lex = Lexer::from_str(input.clone());
                lex.next();
            }
        };
    }

    test_list!(
        read_list_items_one_elem1,
        "{ a }",
        List(vec![Val("a".to_string())])
    );
    test_list!(
        read_list_items_one_elem2,
        "{b}",
        List(vec![Val("b".to_string())])
    );

    test_list!(
        read_list_items_mul_elem1,
        "{ a  b }",
        List(vec![Val("a".to_string()), Val("b".to_string())])
    );
    test_list!(
        read_list_items_mul_elem2,
        "{a  b}",
        List(vec![Val("a".to_string()), Val("b".to_string())])
    );

    test_list!(read_list_fail1, "{ a \n }");
    test_list!(read_list_fail2, "{ \n a }");
    test_list!(read_list_fail3, "{ }");
    test_list!(read_list_fail4, "{}");

    test_next!(next_pass, "pass", Pass);
    test_next!(next_block, "block", Block);
    test_next!(next_proto, "proto", Proto);
    test_next!(next_from, "from", From);
    test_next!(next_to, "to", To);
    test_next!(next_assign, "=", Assign);
    test_next!(next_nl, "\n", Nl);
    test_next!(next_def, "var = val", Def("var".to_string()));
    test_next!(next_ident, "$var", Ident("var".to_string()));
    test_next!(next_val, "var val", Val("var".to_string()));
    test_next!(
        next_list,
        "{ a b }",
        List(vec![Val("a".to_string()), Val("b".to_string())])
    );

    test_next!(next_ident_fail1, "$");
    test_next!(next_ident_fail2, "$ ");
    test_next!(next_ident_fail3, "$\n");

    test_lexer!(
        lex_rule1,
        "block from sip to dip",
        vec![
            Block,
            From,
            Val("sip".to_string()),
            To,
            Val("dip".to_string())
        ]
    );

    test_lexer!(
        lex_rule2,
        "block proto udp from sip to dip",
        vec![
            Block,
            Proto,
            Val("udp".to_string()),
            From,
            Val("sip".to_string()),
            To,
            Val("dip".to_string())
        ]
    );

    test_lexer!(
        lex_rule_with_list,
        "block from { a b } to ip",
        vec![
            Block,
            From,
            List(vec![Val("a".to_string()), Val("b".to_string())]),
            To,
            Val("ip".to_string())
        ]
    );

    test_lexer!(
        lex_rule_with_ident,
        "block proto $var1 from $var2 to $var3",
        vec![
            Block,
            Proto,
            Ident("var1".to_string()),
            From,
            Ident("var2".to_string()),
            To,
            Ident("var3".to_string())
        ]
    );

    test_lexer!(
        lex_with_multiple_new_lines,
        "\n\n block proto a from b to c \n\n\n block proto d from e to f \n\n\n",
        vec![
            Nl,
            Block,
            Proto,
            Val("a".to_string()),
            From,
            Val("b".to_string()),
            To,
            Val("c".to_string()),
            Nl,
            Block,
            Proto,
            Val("d".to_string()),
            From,
            Val("e".to_string()),
            To,
            Val("f".to_string()),
            Nl,
        ]
    );
}
