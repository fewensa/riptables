riptables
===

[![Build Status](https://drone.0u0.me/api/badges/fewensa/riptables/status.svg)](https://drone.0u0.me/fewensa/riptables)


`riptables` provides bindings for [iptables](https://www.netfilter.org/projects/iptables/index.html) application in Linux. (Modified from [rust-iptables](https://github.com/yaa110/rust-iptables))

Relative to [rust-iptables](https://github.com/yaa110/rust-iptables), the parsing function of the call output is added, and the RIPTRule object is returned.


## Usage

```toml
[dependencies]
riptables = "0.1"
```

## Getting started

```rust
use riptables::RIPTables;
use riptables::rule::Archive;

#[test]
fn test_list() {
  let table = "nat";
  let name = "TESTNAT";
  let iptables = riptables::new(false).unwrap();

  iptables.new_chain(table, name);
  iptables.insert(table, name, "-j ACCEPT", 1);
  let rules = iptables.list_chains(table, name).unwrap();
  iptables.delete(table, name, "-j ACCEPT");
  iptables.delete_chain(table, name);

  assert_eq!(rules.len(), 2);

  for rule in rules {
    println!("{:?}", rule);

    assert_eq!(rule.table, "nat".to_string());
    assert_eq!(rule.chain, name.to_string());
    match rule.archive {
      Archive::NewChain => assert_eq!(rule.origin, "-N TESTNAT".to_string()),
      Archive::Append => assert_eq!(rule.origin, "-A TESTNAT -j ACCEPT".to_string()),
      _ => {}
    }
  }
}
```

For more information, please check the test file in `tests` folder.
