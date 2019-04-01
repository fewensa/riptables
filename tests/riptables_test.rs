use std::panic;

use riptables::RIPTables;
use riptables::rule::Archive;

fn riptables() -> RIPTables {
  riptables::new(false).unwrap()
}

//#[test]
//fn test_split() {
//  let vec = riptables::split_quoted("-m comment --comment \"double-quoted comment\" -j ACCEPT");
//  println!("{:?}", vec)
//}

#[test]
fn nat() {
  let table = "nat";
  let old_name = "NATNEW";
  let new_name = "NATNEW2";

  assert_eq!(riptables().new_chain(table, old_name).unwrap(), true);
  assert_eq!(riptables().rename_chain(table, old_name, new_name).unwrap(), true);
  assert_eq!(riptables().append(table, new_name, "-j ACCEPT").unwrap(), true);
  assert_eq!(riptables().exists(table, new_name, "-j ACCEPT").unwrap(), true);
  assert_eq!(riptables().delete(table, new_name, "-j ACCEPT").unwrap(), true);
  assert_eq!(riptables().insert(table, new_name, "-j ACCEPT", 1).unwrap(), true);
  assert_eq!(riptables().append(table, new_name, "-m comment --comment \"double-quoted comment\" -j ACCEPT").unwrap(), true);
  assert_eq!(riptables().exists(table, new_name, "-m comment --comment \"double-quoted comment\" -j ACCEPT").unwrap(), true);
  assert_eq!(riptables().append(table, new_name, "-m comment --comment 'single-quoted comment' -j ACCEPT").unwrap(), true);
  assert_eq!(riptables().exists(table, new_name, "-m comment --comment 'single-quoted comment' -j ACCEPT").unwrap(), true);
  assert_eq!(riptables().flush_chain(table, new_name).unwrap(), true);
  assert_eq!(riptables().exists(table, new_name, "-j ACCEPT").unwrap(), false);
  assert_eq!(riptables().execute(|iptables| iptables.args(&["-t", table, "-A", new_name, "-j", "ACCEPT"])).is_ok(), true);
  assert_eq!(riptables().exists(table, new_name, "-j ACCEPT").unwrap(), true);
  assert_eq!(riptables().flush_chain(table, new_name).unwrap(), true);
  assert_eq!(riptables().exists_chain(table, new_name).unwrap(), true);
  assert_eq!(riptables().delete_chain(table, new_name).unwrap(), true);
  assert_eq!(riptables().exists_chain(table, new_name).unwrap(), false);
}

#[test]
fn test_list() {
  let table = "nat";
  let name = "TESTNAT";
  riptables().new_chain(table, name);
  riptables().insert(table, name, "-j ACCEPT", 1);
  let rules = riptables().list_chains(table, name).unwrap();
  riptables().delete(table, name, "-j ACCEPT");
  riptables().delete_chain(table, name);

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


#[test]
fn filter() {
  let table = "filter";
  let name = "FILTERNEW";

  assert_eq!(riptables().new_chain(table, name).unwrap(), true);
  assert_eq!(riptables().insert(table, name, "-j ACCEPT", 1).unwrap(), true);
  assert_eq!(riptables().replace(table, name, "-j DROP", 1).unwrap(), true);
  assert_eq!(riptables().exists(table, name, "-j DROP").unwrap(), true);
  assert_eq!(riptables().exists(table, name, "-j ACCEPT").unwrap(), false);
  assert_eq!(riptables().delete(table, name, "-j DROP").unwrap(), true);
  assert_eq!(riptables().list_chains(table, name).unwrap().len(), 1);
  assert_eq!(riptables().execute(|iptables| iptables.args(&["-t", table, "-A", name, "-j", "ACCEPT"])).is_ok(), true);
  assert_eq!(riptables().exists(table, name, "-j ACCEPT").unwrap(), true);
  assert_eq!(riptables().append(table, name, "-m comment --comment \"double-quoted comment\" -j ACCEPT").unwrap(), true);
  assert_eq!(riptables().exists(table, name, "-m comment --comment \"double-quoted comment\" -j ACCEPT").unwrap(), true);
  assert_eq!(riptables().append(table, name, "-m comment --comment 'single-quoted comment' -j ACCEPT").unwrap(), true);
  assert_eq!(riptables().exists(table, name, "-m comment --comment \"single-quoted comment\" -j ACCEPT").unwrap(), true);
  assert_eq!(riptables().flush_chain(table, name).unwrap(), true);
  assert_eq!(riptables().exists_chain(table, name).unwrap(), true);
  assert_eq!(riptables().delete_chain(table, name).unwrap(), true);
  assert_eq!(riptables().exists_chain(table, name).unwrap(), false);
}


#[test]
fn test_get_policy() {
  // filter
  assert!(riptables().get_policy("filter", "INPUT").is_ok());
  assert!(riptables().get_policy("filter", "FORWARD").is_ok());
  assert!(riptables().get_policy("filter", "OUTPUT").is_ok());
  // mangle
  assert!(riptables().get_policy("mangle", "PREROUTING").is_ok());
  assert!(riptables().get_policy("mangle", "OUTPUT").is_ok());
  assert!(riptables().get_policy("mangle", "INPUT").is_ok());
  assert!(riptables().get_policy("mangle", "FORWARD").is_ok());
  assert!(riptables().get_policy("mangle", "POSTROUTING").is_ok());
  // nat
  assert!(riptables().get_policy("nat", "PREROUTING").is_ok());
  assert!(riptables().get_policy("nat", "POSTROUTING").is_ok());
  assert!(riptables().get_policy("nat", "OUTPUT").is_ok());
  // raw
  assert!(riptables().get_policy("raw", "PREROUTING").is_ok());
  assert!(riptables().get_policy("raw", "OUTPUT").is_ok());
  // security
  assert!(riptables().get_policy("security", "INPUT").is_ok());
  assert!(riptables().get_policy("security", "OUTPUT").is_ok());
  assert!(riptables().get_policy("security", "FORWARD").is_ok());

  // Wrong table
  assert!(riptables().get_policy("not_existant", "_").is_err());
  // Wrong chain
  assert!(riptables().get_policy("filter", "_").is_err());
}


#[test]
#[ignore]
fn test_set_policy() {

  // Since we can only set policies on built-in chains, we have to retain the policy of the chain
  // before setting it, to restore it to its original state.
  let current_policy = riptables().get_policy("mangle", "FORWARD").unwrap();

  // If the following assertions fail or any other panic occurs, we still have to ensure not to
  // change the policy for the user.
  let result = panic::catch_unwind(|| {
    assert_eq!(riptables().set_policy("mangle", "FORWARD", "DROP").unwrap(), true);
    assert_eq!(riptables().get_policy("mangle", "FORWARD").unwrap(), Some("DROP".to_string()));
  });

  // Reset the policy to the retained value
  riptables().set_policy("mangle", "FORWARD", &current_policy.unwrap()).unwrap();

  // "Rethrow" a potential caught panic
  assert!(result.is_ok());
}


