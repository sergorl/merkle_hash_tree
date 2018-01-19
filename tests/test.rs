//! Test of Merkle hash tree 
#![feature(test)]

extern crate test;
extern crate rand;
extern crate merkle_tree;


extern crate crypto;
extern crate num_cpus;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::Rng;
use merkle_tree::MerkleTree;
use merkle_tree::gen_data;

#[cfg(test)]
mod merkle_test {

    use super::*;
  
    #[test]
    fn crypto_sha256() {

        let size: usize = 32;

        let data: Vec<u8>  = Vec::with_capacity(size);
        let mut coded: Vec<u8> = Vec::with_capacity(size);

        let mut rng = rand::thread_rng(); 

        for _ in 0..size {
            coded.push(rng.gen_range::<u8>(0, 255));
        }

        let mut sha = Sha256::new();

        sha.input(data.as_slice());
        sha.result(coded.as_mut_slice());

        let data_string = match String::from_utf8(data) {
            Ok(v) => v,
            Err(e) => panic!("{}", e),
        };

        println!("String: {:?}", data_string);
        println!("Hash: {:?}", sha.result_str());
    }

    #[test]
    #[should_panic]
    fn crypto_sha256_with_wrong_size_input_block() {

        let size: usize = 31;

        let data: Vec<u8>  = Vec::with_capacity(size);
        let mut coded: Vec<u8> = Vec::with_capacity(size);

        let mut rng = rand::thread_rng(); 

        for _ in 0..size {
            coded.push(rng.gen_range::<u8>(0, 255));
        }

        let mut sha = Sha256::new();

        sha.input(data.as_slice());
        sha.result(coded.as_mut_slice());

        let data_string = match String::from_utf8(data) {
            Ok(v) => v,
            Err(e) => panic!("{}", e),
        };

        println!("String: {:?}", data_string);
        println!("Hash: {:?}", sha.result_str());
    }

    #[test]
    #[should_panic]
    fn create_with_empty() {
        let data: Vec<Vec<u8>> = Vec::with_capacity(1);
        let tree = MerkleTree::new(&data, num_cpus::get());       
    }

    #[test]
    #[should_panic]
    fn create_with_one_wrong_length_data_block_1() {
        let mut data = gen_data(2);
        data[0].clear();
        let tree = MerkleTree::new(&data, num_cpus::get());       
    }

    #[test]
    #[should_panic]
    fn create_with_one_wrong_length_data_block_2() {
        let mut data = gen_data(2);
        data[0].remove(0);
        let tree = MerkleTree::new(&data, num_cpus::get());       
    }

    #[test]
    #[should_panic]
    fn get_wrong_level() {
        let data = gen_data(1);
        let tree = MerkleTree::new(&data, num_cpus::get());       
        tree.get_level(2);
    }

    #[test]
    #[should_panic]
    fn get_hash_with_wrong_level() {
        let data = gen_data(1);
        let tree = MerkleTree::new(&data, num_cpus::get());       
        tree.get_hash(2, 0);
    }

    #[test]
    #[should_panic]
    fn get_hash_with_wrong_index() {
        let data = gen_data(1);
        let tree = MerkleTree::new(&data, num_cpus::get());  
        tree.get_hash(0, 2);
    }

	#[test]
    #[should_panic]
    fn get_parent_with_wrong_level() {
        let data = gen_data(1);
        let tree = MerkleTree::new(&data, num_cpus::get());       
        tree.get_parent(1, 0);
    }

    #[test]
    #[should_panic]
    fn get_parent_with_wrong_index() {
        let data = gen_data(1);
        let tree = MerkleTree::new(&data, num_cpus::get());       
        tree.get_parent(0, 2);
    }

    #[test]
    #[should_panic]
    fn get_child_with_wrong_level_greater() {
        let data = gen_data(1);
        let tree = MerkleTree::new(&data, num_cpus::get());       
        tree.get_children(2, 0);
    }

    #[test]
    #[should_panic]
    fn get_child_with_wrong_level_less() {
        let data = gen_data(1);
        let tree = MerkleTree::new(&data, num_cpus::get());       
        tree.get_children(0, 0);
    }

    #[test]
    #[should_panic]
    fn get_child_with_wrong_index() {
        let data = gen_data(1);
        let tree = MerkleTree::new(&data, num_cpus::get());       
        tree.get_children(1, 2);
    }

}
