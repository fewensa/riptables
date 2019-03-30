use std::vec::Vec;

#[derive(Debug, PartialEq)]
pub enum Archive {
  Policy,
  NewChain,
  Append,
}

#[derive(Debug)]
pub struct RIPTInterface {
  pub negate: bool,
  pub value: String,
}

#[derive(Debug)]
pub struct Extension {
  m: &'static str,
//  item:
}

#[derive(Debug)]
pub struct RIPTRule {
  pub origin: String,
  pub archive: Archive,
  pub chain: String,
  pub input: Option<RIPTInterface>,
  pub output: Option<RIPTInterface>,
  pub protocol: String,
  pub sport: String,
  pub dport: String,
  pub jump: String,
  pub extensions: Vec<Extension>,
}

