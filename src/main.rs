extern crate merkle_tree;
extern crate num_cpus;
extern crate time;

use merkle_tree::MerkleTree;
use merkle_tree::to_hex_string;
use merkle_tree::gen_data;
use time::PreciseTime;
use std::string::ToString;

fn main() {
    // Test 1: one core vs few cores with big data size and small block size
    println!(
        "{}",
        "Test 1: one core vs few cores with big data size and small block size".to_string()
    );

    let mut num_block: usize = 8 * 65536;
    let mut size_block: usize = 32;

    let data_1 = gen_data(num_block, size_block);

    let start = PreciseTime::now();
    let mtree1 = MerkleTree::new(&data_1, num_cpus::get());
    let end = PreciseTime::now();

    println!(
        "Time of parrallel version with number of block {} and block size {}: {}",
        num_block,
        size_block,
        start.to(end)
    );

    let start = PreciseTime::now();
    let mtree2 = MerkleTree::new(&data_1, 1);
    let end = PreciseTime::now();

    println!(
        "Time of sequence version with number of block {} and block size {}: {}",
        num_block,
        size_block,
        start.to(end)
    );

    // Test 2: one core vs few cores with small size data and big block size
    println!(
        "{}",
        "Test 2: one core vs few cores with small size data and big block size".to_string()
    );

    num_block = 8 * 64;
    size_block = 8192;

    let data_1 = gen_data(num_block, size_block);

    let start = PreciseTime::now();
    let mtree1 = MerkleTree::new(&data_1, num_cpus::get());
    let end = PreciseTime::now();

    println!(
        "Time of parrallel version with number of block {} and block size {}: {}",
        num_block,
        size_block,
        start.to(end)
    );

    let start = PreciseTime::now();
    let mtree2 = MerkleTree::new(&data_1, 1);
    let end = PreciseTime::now();

    println!(
        "Time of sequence version with number of block {} and block size {}: {}",
        num_block,
        size_block,
        start.to(end)
    );
}
