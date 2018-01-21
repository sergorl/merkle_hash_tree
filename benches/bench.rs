//! Bench of Merkle hash tree
#![feature(test)]

extern crate merkle_tree;
extern crate num_cpus;
extern crate rand;
extern crate test;

use rand::Rng;
use test::Bencher;
use merkle_tree::MerkleTree;
use merkle_tree::gen_data;

#[bench]
fn bench_one_core_with_small_block_size(b: &mut Bencher) {
    let data = gen_data(8 * 65536, 32);
    b.iter(|| MerkleTree::new(&data, 1));
}

#[bench]
fn bench_one_core_with_big_block_size(b: &mut Bencher) {
    let data = gen_data(16 * 128, 8192);
    b.iter(|| MerkleTree::new(&data, 1));
}

#[bench]
fn bench_few_core_with_small_block_size(b: &mut Bencher) {
    let data = gen_data(8 * 65536, 32);
    b.iter(|| MerkleTree::new(&data, num_cpus::get()));
}

#[bench]
fn bench_few_core_with_big_block_size(b: &mut Bencher) {
    let data = gen_data(16 * 128, 8192);
    b.iter(|| MerkleTree::new(&data, num_cpus::get()));
}
