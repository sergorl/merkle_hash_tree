extern crate merkle_tree;
extern crate num_cpus;
extern crate time;

use merkle_tree::MerkleTree;
use merkle_tree::to_hex_string;
use merkle_tree::gen_data;
use time::PreciseTime;

fn main() {
    let data = gen_data(8 * 65536);

    let start = PreciseTime::now();
    let mtree1 = MerkleTree::new(&data, num_cpus::get());
    let end = PreciseTime::now();

    println!("Time of parrallel version: {}", start.to(end));

    let start = PreciseTime::now();
    let mtree2 = MerkleTree::new(&data, 1);
    let end = PreciseTime::now();

    println!("Time of sequence version: {}", start.to(end));
}
