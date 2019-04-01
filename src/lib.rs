use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::process::Command;

use nix::fcntl::{flock, FlockArg};

use error::{RIPTError, RIPTResult};
use rule::{Archive, RIPTRule};

mod iptparser;
pub mod error;
pub mod rule;


// List of built-in chains taken from: man 8 iptables
const BUILTIN_CHAINS_FILTER: &'static [&'static str] = &["INPUT", "FORWARD", "OUTPUT"];
const BUILTIN_CHAINS_MANGLE: &'static [&'static str] = &["PREROUTING", "OUTPUT", "INPUT", "FORWARD", "POSTROUTING"];
const BUILTIN_CHAINS_NAT: &'static [&'static str] = &["PREROUTING", "POSTROUTING", "OUTPUT"];
const BUILTIN_CHAINS_RAW: &'static [&'static str] = &["PREROUTING", "OUTPUT"];
const BUILTIN_CHAINS_SECURITY: &'static [&'static str] = &["INPUT", "OUTPUT", "FORWARD"];


pub struct RIPTables {
  /// The utility command which must be 'iptables' or 'ip6tables'.
  pub cmd: &'static str,

  /// Indicates if iptables has -C (--check) option
  pub has_check: bool,

  /// Indicates if iptables has -w (--wait) option
  pub has_wait: bool,
}

//#[cfg(not(target_os = "linux"))]
//pub fn new(ipv6: bool) -> RIPTResult<RIPTables> {
//  Err(RIPTError::Other("iptables only works on Linux"))
//}

#[cfg(target_os = "linux")]
pub fn new(ipv6: bool) -> RIPTResult<RIPTables> {
  let cmd = if ipv6 { "ip6tables" } else { "iptables" };
  let version_output = Command::new(cmd).arg("--version").output()?;
  let version_string = String::from_utf8_lossy(&version_output.stdout).into_owned();
  let (v_major, v_minor, v_patch) = iptparser::iptables_version(version_string)?;

  Ok(RIPTables {
    cmd,
    has_check: (v_major > 1) || (v_major == 1 && v_minor > 4) || (v_major == 1 && v_minor == 4 && v_patch > 10),
    has_wait: (v_major > 1) || (v_major == 1 && v_minor > 4) || (v_major == 1 && v_minor == 4 && v_patch > 19),
  })
}

impl RIPTables {
  pub fn execute<T>(&self, caller: T) -> RIPTResult<(i32, String)> where T: Fn(&mut Command) -> &mut Command {
    IptablesCaller::new(self.cmd, caller).call(self.has_wait)
  }

  pub fn get_policy<S>(&self, table: S, chain: S) -> RIPTResult<Option<String>> where S: AsRef<OsStr> + Clone {
    let bchs = self::builtin_chains(table.clone())?;
    if !bchs.iter().as_slice().contains(&&self::to_string(chain.clone())[..]) {
      return Err(RIPTError::Other("given chain is not a default chain in the given table, can't get policy"));
    }

    let (code, output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S").arg(chain.clone()))?;
    if code != 0 {
      return Err(RIPTError::Stderr(output));
    }
    let rules = iptparser::parse_rules(self::to_string(table.clone()), output)?;
    Ok(rules.into_iter()
      .find(|item| item.archive == Archive::Policy && item.chain == self::to_string(chain.clone()))
      .map(|item| item.jump))
  }

  pub fn set_policy<S>(&self, table: S, chain: S, policy: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let bchs = self::builtin_chains(table.clone())?;
    if !bchs.iter().as_slice().contains(&&self::to_string(chain.clone())[..]) {
      return Err(RIPTError::Other("given chain is not a default chain in the given table, can't get policy"));
    }
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-P").arg(chain.clone()).arg(policy.clone()))?;
    Ok(code == 0)
  }

  pub fn insert<S>(&self, table: S, chain: S, rule: S, position: i32) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let rule_vec = iptparser::split_quoted(rule);
    let pstr = position.to_string();
    let args = &[
      &[
        "-t",
        table.as_ref().to_str().unwrap(),
        "-I",
        chain.as_ref().to_str().unwrap(),
        &pstr
      ],
      rule_vec.iter().map(|item| &item[..]).collect::<Vec<&str>>().as_slice()
    ].concat();
    let (code, _output) = self.execute(|iptables| iptables.args(args))?;
    Ok(code == 0)
  }

  pub fn insert_unique<S>(&self, table: S, chain: S, rule: S, position: i32) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    if self.exists(table.clone(), chain.clone(), rule.clone())? {
      return Ok(true);
    }
    self.insert(table.clone(), chain.clone(), rule.clone(), position)
  }

  pub fn replace<S>(&self, table: S, chain: S, rule: S, position: i32) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let rule_vec = iptparser::split_quoted(rule);
    let pstr = position.to_string();
    let args = &[
      &[
        "-t",
        table.as_ref().to_str().unwrap(),
        "-R",
        chain.as_ref().to_str().unwrap(),
        &pstr
      ],
      rule_vec.iter().map(|item| &item[..]).collect::<Vec<&str>>().as_slice()
    ].concat();
    let (code, _output) = self.execute(|iptables| iptables.args(args))?;
    Ok(code == 0)
  }

  pub fn append<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let rule_vec = iptparser::split_quoted(rule);
    let args = &[
      &[
        "-t",
        table.as_ref().to_str().unwrap(),
        "-A",
        chain.as_ref().to_str().unwrap(),
      ],
      rule_vec.iter().map(|item| &item[..]).collect::<Vec<&str>>().as_slice()
    ].concat();
    let (code, _output) = self.execute(|iptables| iptables.args(args))?;
    Ok(code == 0)
  }

  pub fn append_unique<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    if self.exists(table.clone(), chain.clone(), rule.clone())? {
      return Ok(true);
    }
    self.append(table.clone(), chain.clone(), rule.clone())
  }

  pub fn append_replace<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    if self.exists(table.clone(), chain.clone(), rule.clone())? {
      if !self.delete(table.clone(), chain.clone(), rule.clone())? {
        return Ok(false);
      }
    }
    self.append(table, chain, rule)
  }

  pub fn delete<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let rule_vec = iptparser::split_quoted(rule);
    let args = &[
      &[
        "-t",
        table.as_ref().to_str().unwrap(),
        "-D",
        chain.as_ref().to_str().unwrap()
      ],
      rule_vec.iter().map(|item| &item[..]).collect::<Vec<&str>>().as_slice()
    ].concat();
    let (code, _output) = self.execute(|iptables| iptables.args(args))?;
    Ok(code == 0)
  }

  pub fn delete_all<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    while self.exists(table.clone(), chain.clone(), rule.clone())? {
      self.delete(table.clone(), chain.clone(), rule.clone())?;
    }
    Ok(true)
  }

  pub fn list<S>(&self, table: S) -> RIPTResult<Vec<RIPTRule>> where S: AsRef<OsStr> + Clone {
    let (code, output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S"))?;
//    let sodt = "-P OUTPUT  ACCEPT".to_string();
    if code != 0 {
      return Err(RIPTError::Stderr(output));
    }
    Ok(iptparser::parse_rules(self::to_string(table), output)?)
  }

  pub fn chain_names<S>(&self, table: S) -> RIPTResult<Vec<String>> where S: AsRef<OsStr> + Clone {
    Ok(self.list(table)?.iter()
      .filter(|item| item.archive == Archive::Policy || item.archive == Archive::NewChain)
      .map(|item| item.chain.clone())
      .collect::<Vec<String>>())
  }

  pub fn list_chains<S>(&self, table: S, chain: S) -> RIPTResult<Vec<RIPTRule>> where S: AsRef<OsStr> + Clone {
    let (code, output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S").arg(chain.clone()))?;
    if code != 0 {
      return Err(RIPTError::Stderr(output));
    }
    Ok(iptparser::parse_rules(self::to_string(table), output)?)
  }

  pub fn new_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-N").arg(chain.clone()))?;
    Ok(code == 0)
  }

  pub fn delete_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-X").arg(chain.clone()))?;
    Ok(code == 0)
  }

  pub fn rename_chain<S>(&self, table: S, old_chain: S, new_chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-E").arg(old_chain.clone()).arg(new_chain.clone()))?;
    Ok(code == 0)
  }

  pub fn flush_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-F").arg(chain.clone()))?;
    Ok(code == 0)
  }

  pub fn exists_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-L").arg(chain.clone()))?;
    Ok(code == 0)
  }

  pub fn flush_table<S>(&self, table: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-F"))?;
    Ok(code == 0)
  }

  pub fn tables<S>(&self, table: S) -> RIPTResult<Vec<RIPTRule>> where S: AsRef<OsStr> + Clone {
    let (code, output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S"))?;
    if code != 0 {
      return Err(RIPTError::Stderr(output));
    }
    Ok(iptparser::parse_rules(self::to_string(table.clone()), output)?)
  }

  pub fn exists<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    if !self.has_check {
      return self.exists_old_version(table, chain, rule);
    }

    let rule_vec = iptparser::split_quoted(rule);
    let args = &[
      &[
        "-t",
        table.as_ref().to_str().unwrap(),
        "-C",
        chain.as_ref().to_str().unwrap()
      ],
      rule_vec.iter().map(|item| &item[..]).collect::<Vec<&str>>().as_slice()
    ].concat();
    let (code, _output) = self.execute(|iptables| iptables.args(args))?;
    Ok(code == 0)
  }

  fn exists_old_version<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S"))?;
    if code != 0 {
      return Ok(false);
    }
    let exists = output.contains(&format!("-A {} {}", chain.as_ref().to_str().unwrap(), rule.as_ref().to_str().unwrap()));
    Ok(exists)
  }
}

struct IptablesCaller<T> where T: Fn(&mut Command) -> &mut Command {
  command: Command,
  fill: T,
}

impl<T> IptablesCaller<T> where T: Fn(&mut Command) -> &mut Command {
  fn new<S: AsRef<OsStr>>(program: S, fill: T) -> IptablesCaller<T> {
    IptablesCaller {
      command: Command::new(program),
      fill,
    }
  }

  fn call(&mut self, has_wait: bool) -> RIPTResult<(i32, String)> {
    let command = (self.fill)(&mut self.command);

    let mut file_lock = None;

    if has_wait {
      command.arg("--wait");
    } else {
      file_lock = Some(File::create("/var/run/xtables_old.lock")?);

      let mut need_retry = true;
      while need_retry {
        match flock(file_lock.as_ref().unwrap().as_raw_fd(), FlockArg::LockExclusiveNonblock) {
          Ok(_) => need_retry = false,
          Err(e) => if e.errno() == nix::errno::EAGAIN {
            // FIXME: may cause infinite loop
            need_retry = true;
          } else {
            return Err(RIPTError::Nix(e));
          },
        }
      }
    }

    println!("{:?}", command);
    let output = command.output()?;
    if !has_wait {
      if let Some(f) = file_lock {
        drop(f);
      }
    }

    let status = output.status.code();

    match status {
      Some(0) => {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        Ok((0, stdout))
      }
      Some(code) => {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        Ok((code, stderr))
      }
      None => Err(RIPTError::Other("None output code"))
    }
  }
}

fn builtin_chains<S>(table: S) -> RIPTResult<&'static [&'static str]> where S: AsRef<OsStr> + Clone {
  match &self::to_string(table)[..] {
    "filter" => Ok(BUILTIN_CHAINS_FILTER),
    "mangle" => Ok(BUILTIN_CHAINS_MANGLE),
    "nat" => Ok(BUILTIN_CHAINS_NAT),
    "raw" => Ok(BUILTIN_CHAINS_RAW),
    "security" => Ok(BUILTIN_CHAINS_SECURITY),
    _ => Err(RIPTError::Other("given table is not supported by iptables")),
  }
}

fn to_string<S>(text: S) -> String where S: AsRef<OsStr> {
  text.as_ref().to_str().unwrap().to_string()
}
