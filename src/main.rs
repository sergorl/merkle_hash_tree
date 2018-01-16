extern crate merkle_tree;
extern crate num_cpus;

use merkle_tree::MerkleTree;
use merkle_tree::to_hex_string;
use merkle_tree::gen_data;

fn main() {

    let data = gen_data(8);

 	let tree = MerkleTree::new(&data, num_cpus::get());

	println!("{}", tree);
	// println!("{}", to_hex_string(tree.get_root()));	

	// println!("{}", to_hex_string(tree.get_parent(0, 3).unwrap()));
	// println!("{}", to_hex_string(tree.get_parent(0, 2).unwrap()));	
	// println!("{}", to_hex_string(tree.get_parent(0, 7).unwrap()));	
	// println!("{}", to_hex_string(tree.get_parent(2, 0).unwrap()));
	// println!("{}", to_hex_string(tree.get_parent(2, 1).unwrap()));

	let (child1, child2) = tree.get_children(2, 1).unwrap();
	println!("{}", to_hex_string(child1));
	println!("{}", to_hex_string(child2));

	let (child1, child2) = tree.get_children(3, 0).unwrap();
	println!("{}", to_hex_string(child1));
	println!("{}", to_hex_string(child2));

}