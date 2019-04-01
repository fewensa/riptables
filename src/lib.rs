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
  /// Execute iptables command
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert_eq!(iptables.execute(|iptables| iptables.args(&["-t", "nat", "-A", "TESTNAT", "-j", "ACCEPT"])).is_ok(), true);
  /// ```
  pub fn execute<T>(&self, caller: T) -> RIPTResult<(i32, String)> where T: Fn(&mut Command) -> &mut Command {
    IptablesCaller::new(self.cmd, caller).call(self.has_wait)
  }

  /// Get the default policy for a table/chain.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert!(iptables.get_policy("filter", "INPUT").is_ok());
  /// ```
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

  /// Set the default policy for a table/chain.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert_eq!(riptables().set_policy("mangle", "FORWARD", "DROP").unwrap(), true);
  /// ```
  pub fn set_policy<S>(&self, table: S, chain: S, policy: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let bchs = self::builtin_chains(table.clone())?;
    if !bchs.iter().as_slice().contains(&&self::to_string(chain.clone())[..]) {
      return Err(RIPTError::Other("given chain is not a default chain in the given table, can't get policy"));
    }
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-P").arg(chain.clone()).arg(policy.clone()))?;
    Ok(code == 0)
  }

  /// Inserts `rule` in the `position` to the table/chain.
  /// Returns `true` if the rule is inserted.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert_eq!(iptables.insert("nat", "TESTNAT", "-j ACCEPT", 1).unwrap(), true);
  /// ```
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


  /// Inserts `rule` in the `position` to the table/chain if it does not exist.
  /// Returns `true` if the rule is inserted.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert_eq!(iptables.insert_unique("nat", "TESTNAT", "-j ACCEPT", 1).unwrap(), true);
  /// ```
  pub fn insert_unique<S>(&self, table: S, chain: S, rule: S, position: i32) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    if self.exists(table.clone(), chain.clone(), rule.clone())? {
      return Ok(true);
    }
    self.insert(table.clone(), chain.clone(), rule.clone(), position)
  }

  /// Replaces `rule` in the `position` to the table/chain.
  /// Returns `true` if the rule is replaced.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert_eq!(iptables.replace("nat", "TESTNAT", "-j ACCEPT", 1).unwrap(), true);
  /// ```
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


  /// Appends `rule` to the table/chain.
  /// Returns `true` if the rule is appended.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert_eq!(iptables.append("nat", "TESTNAT", "-m comment --comment \"double-quoted comment\" -j ACCEPT").unwrap(), true);
  /// ```
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

  /// Appends `rule` to the table/chain if it does not exist.
  /// Returns `true` if the rule is appended.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert_eq!(iptables.append_unique("nat", "TESTNAT", "-m comment --comment \"double-quoted comment\" -j ACCEPT").unwrap(), true);
  /// ```
  pub fn append_unique<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    if self.exists(table.clone(), chain.clone(), rule.clone())? {
      return Ok(true);
    }
    self.append(table.clone(), chain.clone(), rule.clone())
  }

  /// Appends or replaces `rule` to the table/chain if it does not exist.
  /// Returns `true` if the rule is appended or replaced.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert_eq!(iptables.append_replace("nat", "TESTNAT", "-m comment --comment \"double-quoted comment\" -j ACCEPT").unwrap(), true);
  /// ```
  pub fn append_replace<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    if self.exists(table.clone(), chain.clone(), rule.clone())? {
      if !self.delete(table.clone(), chain.clone(), rule.clone())? {
        return Ok(false);
      }
    }
    self.append(table, chain, rule)
  }

  /// Deletes `rule` from the table/chain.
  /// Returns `true` if the rule is deleted.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert_eq!(riptables.delete("nat", "TESTNAT", "-j ACCEPT").unwrap(), true);
  /// ```
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

  /// Deletes all repetition of the `rule` from the table/chain.
  /// Returns `true` if the rules are deleted.
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert_eq!(riptables.delete_all("nat", "TESTNAT", "-j ACCEPT").unwrap(), true);
  /// ```
  pub fn delete_all<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    while self.exists(table.clone(), chain.clone(), rule.clone())? {
      self.delete(table.clone(), chain.clone(), rule.clone())?;
    }
    Ok(true)
  }

  /// Lists rules in the table/chain.
  ///
  /// # Example
  ///
  /// ```rust
  /// use riptables::rule::{Archive, RIPTRule};
  ///
  /// let iptables = riptables::new(false).unwrap();
  ///
  /// let table = "nat";
  /// let name = "TESTNAT";
  /// riptables.new_chain(table, name).unwrap();
  /// riptables.insert(table, name, "-j ACCEPT", 1).unwrap();
  /// let rules: Vec<RIPTRule> = riptables.list(table, name).unwrap();
  /// riptables.delete(table, name, "-j ACCEPT").unwrap();
  /// riptables.delete_chain(table, name).unwrap();
  ///
  /// assert_eq!(rules.len(), 2);
  ///
  /// for rule in rules {
  ///   println!("{:?}", rule);
  ///
  ///   assert_eq!(rule.table, "nat".to_string());
  ///   assert_eq!(rule.chain, name.to_string());
  ///   match rule.archive {
  ///     Archive::NewChain => assert_eq!(rule.origin, "-N TESTNAT".to_string()),
  ///     Archive::Append => assert_eq!(rule.origin, "-A TESTNAT -j ACCEPT".to_string()),
  ///     _ => {}
  ///   }
  /// }
  /// ```
  pub fn list<S>(&self, table: S) -> RIPTResult<Vec<RIPTRule>> where S: AsRef<OsStr> + Clone {
    let (code, output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S"))?;
//    let sodt = "-P OUTPUT  ACCEPT".to_string();
    if code != 0 {
      return Err(RIPTError::Stderr(output));
    }
    Ok(iptparser::parse_rules(self::to_string(table), output)?)
  }


  /// Lists the name of each chain in the table.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// let names = iptables.chain_names("nat");
  /// ```
  pub fn chain_names<S>(&self, table: S) -> RIPTResult<Vec<String>> where S: AsRef<OsStr> + Clone {
    Ok(self.list(table)?.iter()
      .filter(|item| item.archive == Archive::Policy || item.archive == Archive::NewChain)
      .map(|item| item.chain.clone())
      .collect::<Vec<String>>())
  }

  /// Lists rules in the table/chain.
  ///
  /// # Example
  ///
  /// ```rust
  /// use riptables::rule::RIPTRule;
  /// let iptables = riptables::new(false).unwrap();
  /// let rules: Vec<RIPTRule> = riptables.list_chains(table, name).unwrap();
  /// ```
  pub fn list_chains<S>(&self, table: S, chain: S) -> RIPTResult<Vec<RIPTRule>> where S: AsRef<OsStr> + Clone {
    let (code, output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S").arg(chain.clone()))?;
    if code != 0 {
      return Err(RIPTError::Stderr(output));
    }
    Ok(iptparser::parse_rules(self::to_string(table), output)?)
  }

  /// Creates a new user-defined chain.
  /// Returns `true` if the chain is created.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// iptables.new_chain("nat", "TESTNAT");
  /// ```
  pub fn new_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-N").arg(chain.clone()))?;
    Ok(code == 0)
  }

  /// Deletes a user-defined chain in the table.
  /// Returns `true` if the chain is deleted.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// iptables.delete_chain("nat", "TESTNAT");
  /// ```
  pub fn delete_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-X").arg(chain.clone()))?;
    Ok(code == 0)
  }

  /// Renames a chain in the table.
  /// Returns `true` if the chain is renamed.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// iptables.rename_chain("nat", "TESTNAT", "OTHERNAME");
  /// ```
  pub fn rename_chain<S>(&self, table: S, old_chain: S, new_chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-E").arg(old_chain.clone()).arg(new_chain.clone()))?;
    Ok(code == 0)
  }

  /// Flushes (deletes all rules) a chain.
  /// Returns `true` if the chain is flushed.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// iptables.flush_chain("nat", "TESTNAT");
  /// ```
  pub fn flush_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-F").arg(chain.clone()))?;
    Ok(code == 0)
  }

  /// Checks for the existence of the `chain` in the table.
  /// Returns true if the chain exists.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// iptables.exists_chain("nat", "TESTNAT");
  /// ```
  pub fn exists_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-L").arg(chain.clone()))?;
    Ok(code == 0)
  }

  /// Flushes all chains in a table.
  /// Returns `true` if the chains are flushed.
  ///
  /// # Example
  ///
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// iptables.flush_table("nat");
  /// ```
  pub fn flush_table<S>(&self, table: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let (code, _output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-F"))?;
    Ok(code == 0)
  }

  /// Lists rules in the table.
  ///
  /// # Example
  ///
  /// ```rust
  /// use riptables::rule::RIPTRule;
  ///
  /// let iptables = riptables::new(false).unwrap();
  /// let rule: Vec<RIPTRule> = iptables.list_tables("nat").unwrap();
  /// ```
  pub fn list_tables<S>(&self, table: S) -> RIPTResult<Vec<RIPTRule>> where S: AsRef<OsStr> + Clone {
    let (code, output) = self.execute(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S"))?;
    if code != 0 {
      return Err(RIPTError::Stderr(output));
    }
    Ok(iptparser::parse_rules(self::to_string(table.clone()), output)?)
  }

  /// Checks for the existence of the `rule` in the table/chain.
  /// Returns true if the rule exists.
  /// 
  /// # Example
  /// 
  /// ```rust
  /// let iptables = riptables::new(false).unwrap();
  /// assert_eq!(riptables.exists(table, "TESTNAT", "-j ACCEPT").unwrap(), true);
  /// ```
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
