use dep::poseidon::poseidon::bn254::hash_2;
use std::hash::poseidon::bn254::hash_3;

fn selector(a: Field, b: Field, sel: Field) -> Field {
  assert(sel * (1 - sel) == 0, "sel must be 0 or 1");
  if sel == 0 { a } else { b }
}

fn merkle_inclusion_proof<let N: u32>(
  leaf: Field, 
  path_elements: [Field; N], 
  path_indices: [Field; N]
) -> Field {
  let mut current = leaf;
  for i in 0..N {
    let left  = selector(current, path_elements[i], path_indices[i]);
    let right = selector(path_elements[i], current, path_indices[i]);
    current = hash_2([left, right]);
  }
  current
}

fn withdraw<let N: u32>(
  secret: [Field; 2],
  loan_amount: Field,
  nullifier: Field,
  path_elements: [Field; N],
  path_indices: [Field; N],
  root: Field
) -> Field {
  let commitment = hash_3([secret[0], secret[1], loan_amount]);
  assert(commitment == nullifier, "nullifier mismatch");

  let computed_root = merkle_inclusion_proof(commitment, path_elements, path_indices);
  assert(computed_root == root, "invalid merkle proof");

  loan_amount
}

fn main(
  secret: [Field; 2],
  loan_amount: Field, 
  nullifier: Field, 
  path_elements: [Field; 2], 
  path_indices: [Field; 2], 
  root: Field
) -> pub Field {
  withdraw(secret, loan_amount, nullifier, path_elements, path_indices, root)
}

#[test]
fn test_withdraw_valid() {
  let secret = [1, 2];
  let loan_amount = 90;
  let nullifier = hash_3([secret[0], secret[1], loan_amount]);

  let leaf = nullifier;
  let path_elements = [3, 4];
  let path_indices = [0, 1];

  let mut root = hash_2([leaf, path_elements[0]]);
  root = hash_2([path_elements[1], root]);

  let public_output = main(
    secret, 
    loan_amount, 
    nullifier, 
    path_elements, 
    path_indices, 
    root
  );

  assert(public_output == loan_amount);
}

#[test(should_fail)]
fn test_withdraw_nullifier_fail() {
  let secret = [1, 2];
  let loan_amount = 100;
  let nullifier = hash_3([1, 2, 101]);
  let path_elements = [10, 20];
  let path_indices = [0, 1];
  let root = merkle_inclusion_proof(hash_3([1, 2, 100]), path_elements, path_indices);

  let _ = withdraw(secret, loan_amount, nullifier, path_elements, path_indices, root);
}

#[test(should_fail)]
fn test_withdraw_merkle_fail() {
  let secret = [1, 2];
  let loan_amount = 100;
  let nullifier = hash_3([1, 2, 100]);
  let path_elements = [10, 20];
  let path_indices = [0, 0];
  let root = merkle_inclusion_proof(nullifier, [10, 20], [0, 1]);

  let _ = withdraw(secret, loan_amount, nullifier, path_elements, path_indices, root);
}

#[test(should_fail)]
fn test_selector_fail() {
  let _ = selector(5, 10, 2);
}
