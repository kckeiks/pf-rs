pub const PASS: &str = "pass";
pub const BLOCK: &str = "block";
pub const PROTO: &str = "proto";
pub const ON: &str = "on";
pub const FROM: &str = "from";
pub const TO: &str = "to";
pub const NEWLINE: &str = "\n";
pub const PORT: &str = "port";

// These two will be used by preprocessor
pub const ASSIGN_PATTERN: &str = "=";
pub const IDEN_PATTERN: &str = "$";

#[derive(Debug, PartialEq)]
pub enum Token {
    Assign(String),
    Block,
    From(String),
    Identifier(String),
    NewLine(String),
    Pass,
    Proto(String),
    On(String),
    To(String),
    Value(String),
    Port(String),
}
