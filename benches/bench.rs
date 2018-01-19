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
    	let data = gen_data(512);           
        MerkleTree::new(&data, 1)     
    });
}

#[bench]
fn bench_few_core(b: &mut Bencher) {
    b.iter(|| {         
    	let data = gen_data(512);   
        MerkleTree::new(&data, num_cpus::get())     
    });
}




