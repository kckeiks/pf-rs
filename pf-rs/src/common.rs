pub const ALL: &str = "all";
pub const PASS: &str = "pass";
pub const BLOCK: &str = "block";
pub const PROTO: &str = "proto";
pub const ON: &str = "on";
pub const FROM: &str = "from";
pub const TO: &str = "to";
pub const PORT: &str = "port";
pub const NL: char = '\n';
pub const ASSIGN: char = '=';
pub const REPLACE_PREFIX: char = '$';
pub const OPEN_CBRACK: char = '{';
pub const CLOSE_CBRACK: char = '}';

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    All,
    Assign,
    Block,
    From,
    Nl,
    Pass,
    Proto,
    On,
    To,
    Port,
    Expr(String),
    List(Vec<Self>),
    Ident(String),
}
