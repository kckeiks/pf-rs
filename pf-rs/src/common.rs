pub const PASS: &str = "pass";
pub const BLOCK: &str = "block";
pub const PROTO: &str = "proto";
pub const ON: &str = "on";
pub const FROM: &str = "from";
pub const TO: &str = "to";
pub const PORT: &str = "port";

#[derive(Debug, PartialEq)]
pub enum Token {
    Block,
    From(String),
    Pass,
    Proto(String),
    On(String),
    To(String),
    Port(String),
}
