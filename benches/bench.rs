#![feature(test)]

extern crate test;
extern crate rand;
extern crate merkle_tree;
extern crate num_cpus;

use rand::Rng;
use test::Bencher;
use merkle_tree::MerkleTree;
use merkle_tree::gen_data;

#[bench]
fn bench_one_core(b: &mut Bencher) {
    b.iter(|| {            
        MerkleTree::new(&gen_data(512), 1)     
    });
}

#[bench]
fn bench_few_core(b: &mut Bencher) {
    b.iter(|| {            
        MerkleTree::new(&gen_data(512), 16)     
    });
}

// #[bench]
// fn bench_xor_1000_ints(b: &mut Bencher) {
//     b.iter(|| {
//         let n = test::black_box(100);
//         (0..n).fold(0, |a, b| a ^ b)
//     });
// }



