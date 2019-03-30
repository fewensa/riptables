use std::process::Command;

use riptables::RIPTables;

fn riptables() -> RIPTables {
  riptables::new(false).unwrap()
}

#[test]
fn test_list() {
  let result = riptables().list("filter");
  println!("{:#?}", result);
}

#[test]
fn test_chain_names() {
  let result = riptables().chain_names("filter");
  println!("{:#?}", result);
}

#[test]
fn test_chains() {
  let result = riptables().chains("filter", "INPUT");
  println!("{:#?}", result);
}

#[test]
fn test_new_chain() {
  let result = riptables().new_chain("filter", "test");
  println!("{:?}", result);
}

#[test]
fn test_delete_chain() {
  let result = riptables().delete_chain("filter", "test");
  println!("{:?}", result);
}

#[test]
fn test_tables() {
  let result = riptables().tables("nat");
  println!("{:#?}", result);
}

#[test]
fn test_exists_chain() {
  let result = riptables().exists_chain("filter", "test");
  println!("{:?}", result);
}
