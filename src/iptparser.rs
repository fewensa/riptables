use string_builder::Builder;
use text_reader::TextReader;

use crate::error::{RIPTAnalysisError, RIPTAnalysisResult};
use crate::rule::{Archive, RIPTInterface, RIPTRule};

pub fn parse_rules(text: String) -> RIPTAnalysisResult<Vec<RIPTRule>> {
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
        let rule = self::to_rule(line_text)?;
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
    let rule = self::to_rule(line_text)?;
    rets.push(rule);
  }

  Ok(rets)
}

fn to_rule(text: String) -> RIPTAnalysisResult<RIPTRule> {
//  println!("{:?}", text);

  let mut reader = TextReader::new(text.clone());

  let mut psmp = vec![];
  let mut entry = false;

  let mut builder = Builder::default();
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
            iptrtup.arg = builder.string().unwrap();
            builder = Builder::default();
            times = 1;
          }
          1 => {
            iptrtup.value.push(builder.string().unwrap());
            builder = Builder::default();
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
  iptrtup.value.push(builder.string().unwrap());
  psmp.push(iptrtup.clone());

//  println!("{:#?}", psmp);


  let mut rule = RIPTRule {
    origin: text.clone(),
    archive: Archive::Policy,
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
