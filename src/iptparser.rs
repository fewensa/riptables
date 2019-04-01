use std::ffi::OsStr;

use rstring_builder::StringBuilder;
use text_reader::TextReader;

use crate::error::{RIPTAnalysisError, RIPTAnalysisResult, RIPTResult};
use crate::rule::{Archive, RIPTInterface, RIPTRule};

pub fn parse_rules(table: String, text: String) -> RIPTAnalysisResult<Vec<RIPTRule>> {
  let mut rets = vec![];
  let mut reader = TextReader::new(text);
  let mut builder = vec![];
  while reader.has_next() {
    let ch = reader.next();
    match ch {
      Some('\n') => {
        let line_text = builder.iter()
          .filter(|item: &&Option<char>| item.is_some())
          .map(|item: &Option<char>| item.unwrap())
          .into_iter()
          .collect();
        let rule = self::to_rule(table.clone(), line_text)?;
        rets.push(rule);

        builder.clear();
      }
      _ => builder.push(ch)
    }
  }

  let line_text: String = builder.iter()
    .filter(|item: &&Option<char>| item.is_some())
    .map(|item: &Option<char>| item.unwrap())
    .into_iter()
    .collect();
  if !line_text.is_empty() {
    let rule = self::to_rule(table.clone(), line_text)?;
    rets.push(rule);
  }

  Ok(rets)
}

fn to_rule(table: String, text: String) -> RIPTAnalysisResult<RIPTRule> {
//  println!("{:?}", text);

  let mut reader = TextReader::new(text.clone());

  let mut psmp = vec![];
  let mut entry = false;

  let mut builder = StringBuilder::new();
  let mut iptrtup = IPTRTup::new();
  let mut times = 0;
  let mut negate = false;
  let mut multi = false;

  while reader.has_next() {
    match reader.next() {
      Some('-') => {
        if times == 1 {
          builder.append('-');
          continue;
        }
        if !entry {
          entry = true;
          continue;
        }
        if let Some('-') = reader.next() {
          continue;
        }
        reader.back();
        psmp.push(iptrtup.clone());
        iptrtup.clear();
      }
      Some('!') => {
        psmp.push(iptrtup.clone());
        iptrtup.clear();
        negate = true;
        entry = false;
      }
      Some(' ') => {
        if multi {
          builder.append(' ');
          continue;
        }
        while reader.has_next() {
          if let Some(' ') = reader.next() {
            continue;
          }
          break;
        }
        reader.back();
        match times {
          0 => {
            if negate {
              iptrtup.negate = true;
              negate = false;
              continue;
            }
            iptrtup.arg = builder.string();
            builder.clear();
            times = 1;
          }
          1 => {
            iptrtup.value.push(builder.string());
            builder.clear();
            times = 0;
          }
          _ => {}
        }
      }
      Some('"') => multi = !multi,
      Some(ch) => {
        builder.append(ch);
      }
      _ => return Err(RIPTAnalysisError::UnexpectedOutput(text.clone()))
    }
  }
  iptrtup.value.push(builder.string());
  psmp.push(iptrtup.clone());

//  println!("{:#?}", psmp);


  let mut rule = RIPTRule {
    origin: text.clone(),
    archive: Archive::Policy,
    table,
    chain: "".to_string(),
    input: None,
    output: None,
    protocol: "".to_string(),
    sport: "".to_string(),
    dport: "".to_string(),
    jump: "".to_string(),
    extensions: vec![],
  };

  psmp.iter().for_each(|item| {
    match &item.arg[..] {
      "A" => {
        rule.archive = Archive::Append;
        rule.chain = item.value[0].clone();
      }
      "P" => {
        rule.archive = Archive::Policy;
        rule.chain = item.value[0].clone();
        rule.jump = item.value[1].clone();
      }
      "N" => {
        rule.archive = Archive::NewChain;
        rule.chain = item.value[0].clone();
      }
      "i" => rule.input = Some(RIPTInterface { negate: item.negate, value: item.value[0].clone() }),
      "o" => rule.output = Some(RIPTInterface { negate: item.negate, value: item.value[0].clone() }),
      "p" => rule.protocol = item.value[0].clone(),
      "sport" => rule.sport = item.value[0].clone(),
      "dport" => rule.dport = item.value[0].clone(),
      "j" => rule.jump = item.value[0].clone(),
      _ => {}
    }
  });

  Ok(rule)
}


pub fn split_quoted<S>(text: S) -> Vec<String> where S: AsRef<OsStr> {
  let mut rets = vec![];
  let mut reader = TextReader::new(text);
  let mut quoted_p = false; // "
  let mut quoted_b = false; // '
  let mut builder = StringBuilder::new();
  while reader.has_next() {
    match reader.next() {
      Some('"') => {
        if quoted_b {
          builder.append('"');
          continue;
        }
        quoted_p = !quoted_p;
        continue;
      }
      Some('\'') => {
        if quoted_p {
          builder.append('\'');
          continue;
        }
        quoted_b = !quoted_b;
        continue;
      }
      Some(' ') => {
        if quoted_p || quoted_b {
          builder.append(' ');
          continue;
        }
        rets.push(builder.string());
        builder.clear();
        continue;
      }
      Some(ch) => {
        builder.append(ch);
        continue;
      }
      None => continue
    }
  }
  if !builder.is_empty() {
    let string = builder.string();
    rets.push(string);
    builder.clear();
  }

  rets
}


pub fn iptables_version(text: String) -> RIPTResult<(i32, i32, i32)> {
  let mut reader = TextReader::new(text);
  let mut version = Vec::with_capacity(3);
  let mut builder = StringBuilder::new();
  let mut entry = false;
//  let mut legacy = false;
  while reader.has_next() {
    match reader.next() {
      Some('v') => entry = true,
      Some('.') => {
        if !entry {
          continue;
        }
        let vti = builder.string();
        let vtn = vti.parse::<i32>()?;
        version.push(vtn);
        builder.clear();
      }
      Some(' ') => {
        if !entry {
          continue;
        }
//        legacy = true;
        break;
      }
      Some(ch) => {
        if !entry {
          continue;
        }
        builder.append(ch);
      }
      None => continue
    }
  }

  let vti = builder.string();
  let vtn = vti.parse::<i32>()?;
  version.push(vtn);
  builder.clear();
  return Ok((version[0], version[1], version[2]));
}


#[derive(Debug)]
struct IPTRTup {
  arg: String,
  value: Vec<String>,
  negate: bool,
}

impl IPTRTup {
  fn new() -> IPTRTup {
    IPTRTup {
      arg: "".to_string(),
      value: vec![],
      negate: false,
    }
  }

  fn clear(&mut self) -> &IPTRTup {
    self.arg.clear();
    self.value.clear();
    self.negate = false;
    self
  }
}

impl Clone for IPTRTup {
  fn clone(&self) -> Self {
    IPTRTup {
      arg: self.arg.clone(),
      value: self.value.clone(),
      negate: self.negate,
    }
  }
}
