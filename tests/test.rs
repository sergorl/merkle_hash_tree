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

pub fn add_two(a: i32) -> i32 {
    a + 2
}

#[cfg(test)]
mod merkle_test {

    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(4, add_two(2));
    }    

    #[test]
    fn test_sha256() {

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
    fn test_get_child_1() {

        let data = gen_data(1);
        let tree = MerkleTree::new(&data, num_cpus::get());
        
        tree.get_children(0, 0);
    }

    #[test]
    #[should_panic]
    fn test_get_child_2() {

        let data = gen_data(1);
        let tree = MerkleTree::new(&data, num_cpus::get());
        
        tree.get_children(3, 0); 
    }

}
