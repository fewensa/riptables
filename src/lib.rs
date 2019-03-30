#[macro_use]
extern crate lazy_static;

use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::process::Command;

use nix::fcntl::{flock, FlockArg};
use regex::{Match, Regex};

use error::{RIPTError, RIPTResult};
use rule::{Archive, RIPTInterface, RIPTRule};

mod iptparser;
pub mod error;
pub mod rule;


// List of built-in chains taken from: man 8 iptables
const BUILTIN_CHAINS_FILTER: &'static [&'static str] = &["INPUT", "FORWARD", "OUTPUT"];
const BUILTIN_CHAINS_MANGLE: &'static [&'static str] = &["PREROUTING", "OUTPUT", "INPUT", "FORWARD", "POSTROUTING"];
const BUILTIN_CHAINS_NAT: &'static [&'static str] = &["PREROUTING", "POSTROUTING", "OUTPUT"];
const BUILTIN_CHAINS_RAW: &'static [&'static str] = &["PREROUTING", "OUTPUT"];
const BUILTIN_CHAINS_SECURITY: &'static [&'static str] = &["INPUT", "OUTPUT", "FORWARD"];


lazy_static! {
    static ref RE_SPLIT: Regex = Regex::new(r#"["'].+?["']|[^ ]+"#).unwrap();
}

trait SplitQuoted {
  fn split_quoted(&self) -> Vec<&str>;
}

impl SplitQuoted for str {
  fn split_quoted(&self) -> Vec<&str> {
    RE_SPLIT
      // Iterate over matched segments
      .find_iter(self)
      // Get match as str
      .map(|m| Match::as_str(&m))
      // Remove any surrounding quotes (they will be reinserted by `Command`)
      .map(|s| s.trim_matches(|c| c == '"' || c == '\''))
      // Collect
      .collect::<Vec<_>>()
  }
}


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
  let re = Regex::new(r"v(\d+)\.(\d+)\.(\d+)")?;
  let version_string = String::from_utf8_lossy(&version_output.stdout).into_owned();
  let versions = re.captures(&version_string).ok_or("invalid version number")?;
  let v_major = versions.get(1).ok_or("unable to get major version number")?.as_str().parse::<i32>()?;
  let v_minor = versions.get(2).ok_or("unable to get minor version number")?.as_str().parse::<i32>()?;
  let v_patch = versions.get(3).ok_or("unable to get patch version number")?.as_str().parse::<i32>()?;


  Ok(RIPTables {
    cmd,
    has_check: (v_major > 1) || (v_major == 1 && v_minor > 4) || (v_major == 1 && v_minor == 4 && v_patch > 10),
    has_wait: (v_major > 1) || (v_major == 1 && v_minor > 4) || (v_major == 1 && v_minor == 4 && v_patch > 19),
  })
}

impl RIPTables {
  pub fn list<S>(&self, table: S) -> RIPTResult<Vec<RIPTRule>> where S: AsRef<OsStr> + Clone {
    let stdout = self.call(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S"))?;
//    let sodt = "-P OUTPUT  ACCEPT".to_string();
    Ok(iptparser::parse_rules(stdout)?)
  }

  pub fn chain_names<S>(&self, table: S) -> RIPTResult<Vec<String>> where S: AsRef<OsStr> + Clone {
    Ok(self.list(table)?.iter()
      .filter(|item| item.archive == Archive::Policy || item.archive == Archive::NewChain)
      .map(|item| item.chain.clone())
      .collect::<Vec<String>>())
  }

  pub fn chains<S>(&self, table: S, chain: S) -> RIPTResult<Vec<RIPTRule>> where S: AsRef<OsStr> + Clone {
    let stdout = self.call(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S").arg(chain.clone()))?;
    Ok(iptparser::parse_rules(stdout)?)
  }

  pub fn new_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    self.call(|iptables| iptables.arg("-t").arg(table.clone()).arg("-N").arg(chain.clone()))?;
    Ok(true)
  }

  pub fn delete_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    self.call(|iptables| iptables.arg("-t").arg(table.clone()).arg("-X").arg(chain.clone()))?;
    Ok(true)
  }

  pub fn rename_chain<S>(&self, table: S, old_chain: S, new_chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    self.call(|iptables| iptables.arg("-t").arg(table.clone()).arg("-E").arg(old_chain.clone()).arg(new_chain.clone()))?;
    Ok(true)
  }

  pub fn flush_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    self.call(|iptables| iptables.arg("-t").arg(table.clone()).arg("-F").arg(chain.clone()))?;
    Ok(true)
  }

  pub fn exists_chain<S>(&self, table: S, chain: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let result = self.call(|iptables| iptables.arg("-t").arg(table.clone()).arg("-L").arg(chain.clone()));
    // fixme: Ok(false)
    Ok(true)
  }

  pub fn flush_table<S>(&self, table: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    self.call(|iptables| iptables.arg("-t").arg(table.clone()).arg("-F"))?;
    Ok(true)
  }

  pub fn tables<S>(&self, table: S) -> RIPTResult<Vec<RIPTRule>> where S: AsRef<OsStr> + Clone {
    let stdout = self.call(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S"))?;
    Ok(iptparser::parse_rules(stdout)?)
  }

  pub fn exists_rule<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    if !self.has_check {
      return self.exists_old_version(table, chain, rule);
    }

    let args = &[&["-t", table.as_ref().to_str().unwrap(), "-C", chain.as_ref().to_str().unwrap()], rule.as_ref().to_str().unwrap().split_quoted().as_slice()].concat();
    self.call(|iptables| iptables.args(args))?;
    Ok(true)
  }


  fn exists_old_version<S>(&self, table: S, chain: S, rule: S) -> RIPTResult<bool> where S: AsRef<OsStr> + Clone {
    let output = self.call(|iptables| iptables.arg("-t").arg(table.clone()).arg("-S"))?;
    let exists = output.contains(&format!("-A {} {}", chain.as_ref().to_str().unwrap(), rule.as_ref().to_str().unwrap()));
    Ok(exists)
  }

  fn call<T>(&self, caller: T) -> RIPTResult<String> where T: Fn(&mut Command) -> &mut Command {
    IptablesCaller::new(self.cmd, caller).call(self.has_wait)
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

  fn call(&mut self, has_wait: bool) -> RIPTResult<String> {
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
        Ok(stdout)
      }
      Some(code) => {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let msg = format!("Command execute faild: {}:{}", code, stderr);
        let m = Box::leak(msg.into_boxed_str());
        Err(RIPTError::Other(m))
      }
      None => Err(RIPTError::Other("None output code"))
    }
  }
}



