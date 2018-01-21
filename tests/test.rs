//! Test of Merkle hash tree
#![feature(test)]

extern crate crypto;
extern crate merkle_tree;
extern crate num_cpus;
extern crate rand;
extern crate test;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::Rng;
use merkle_tree::MerkleTree;
use merkle_tree::gen_data;

#[cfg(test)]
mod crypto_test {

    use super::*;

    fn sha256(size: usize) {
        let data: Vec<u8> = Vec::with_capacity(size);
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
    fn sha256_with_min_size_input() {
        sha256(32);
    }

    #[test]
    #[should_panic]
    fn sha256_with_wrong_size_input() {
        sha256(32 - 1);
    }
}

#[cfg(test)]
mod merkle_test {

    use super::*;

    #[test]
    #[should_panic]
    fn create_with_empty() {
        let data: Vec<Vec<u8>> = Vec::with_capacity(1);
        let tree = MerkleTree::new(&data, num_cpus::get());
    }

    #[test]
    #[should_panic]
    fn create_with_one_wrong_length_data_block_1() {
        let mut data = gen_data(2, 32);
        data[0].clear();
        let tree = MerkleTree::new(&data, num_cpus::get());
    }

    #[test]
    #[should_panic]
    fn create_with_one_wrong_length_data_block_2() {
        let mut data = gen_data(2, 32);
        data[0].remove(0);
        let tree = MerkleTree::new(&data, num_cpus::get());
    }

    #[test]
    #[should_panic]
    fn get_wrong_level() {
        let data = gen_data(1, 32);
        let tree = MerkleTree::new(&data, num_cpus::get());
        tree.get_level(2);
    }

    #[test]
    #[should_panic]
    fn get_hash_with_wrong_level() {
        let data = gen_data(1, 32);
        let tree = MerkleTree::new(&data, num_cpus::get());
        tree.get_hash(2, 0);
    }

    #[test]
    #[should_panic]
    fn get_hash_with_wrong_index() {
        let data = gen_data(1, 32);
        let tree = MerkleTree::new(&data, num_cpus::get());
        tree.get_hash(0, 2);
    }

    #[test]
    #[should_panic]
    fn get_parent_with_wrong_level() {
        let data = gen_data(1,32);
        let tree = MerkleTree::new(&data, num_cpus::get());
        tree.get_parent(1, 0);
    }

    #[test]
    #[should_panic]
    fn get_parent_with_wrong_index() {
        let data = gen_data(1, 32);
        let tree = MerkleTree::new(&data, num_cpus::get());
        tree.get_parent(0, 2);
    }

    #[test]
    fn get_parent() {
        let data = gen_data(5, 32);
        let tree = MerkleTree::new(&data, num_cpus::get());

        assert_eq!(tree.get_parent(2, 0), tree.get_root());
        assert_eq!(tree.get_parent(2, 1), tree.get_root());
        assert_eq!(tree.get_parent(1, 0), tree.get_hash(2, 0));
        assert_eq!(tree.get_parent(1, 1), tree.get_hash(2, 0));
        assert_eq!(tree.get_parent(1, 2), tree.get_hash(2, 1));
        assert_eq!(tree.get_parent(1, 3), tree.get_hash(2, 1));
        assert_eq!(tree.get_parent(0, 0), tree.get_hash(1, 0));
        assert_eq!(tree.get_parent(0, 1), tree.get_hash(1, 0));
        assert_eq!(tree.get_parent(0, 2), tree.get_hash(1, 1));
        assert_eq!(tree.get_parent(0, 3), tree.get_hash(1, 1));
        assert_eq!(tree.get_parent(0, 4), tree.get_hash(1, 2));
        assert_eq!(tree.get_parent(0, 5), tree.get_hash(1, 2));
    }

    #[test]
    #[should_panic]
    fn get_child_with_wrong_level_greater() {
        let data = gen_data(1, 32);
        let tree = MerkleTree::new(&data, num_cpus::get());
        tree.get_children(2, 0);
    }

    #[test]
    #[should_panic]
    fn get_child_with_wrong_level_less() {
        let data = gen_data(1, 32);
        let tree = MerkleTree::new(&data, num_cpus::get());
        tree.get_children(0, 0);
    }

    #[test]
    #[should_panic]
    fn get_child_with_wrong_index() {
        let data = gen_data(1, 32);
        let tree = MerkleTree::new(&data, num_cpus::get());
        tree.get_children(1, 2);
    }

    #[test]
    fn get_child() {
        let data = gen_data(5, 32);
        let tree = MerkleTree::new(&data, num_cpus::get());

        assert_eq!(
            tree.get_children(3, 0),
            (tree.get_hash(2, 0), tree.get_hash(2, 1))
        );
        assert_eq!(
            tree.get_children(2, 0),
            (tree.get_hash(1, 0), tree.get_hash(1, 1))
        );
        assert_eq!(
            tree.get_children(2, 1),
            (tree.get_hash(1, 2), tree.get_hash(1, 3))
        );
        assert_eq!(
            tree.get_children(1, 0),
            (tree.get_hash(0, 0), tree.get_hash(0, 1))
        );
        assert_eq!(
            tree.get_children(1, 1),
            (tree.get_hash(0, 2), tree.get_hash(0, 3))
        );
        assert_eq!(
            tree.get_children(1, 2),
            (tree.get_hash(0, 4), tree.get_hash(0, 5))
        );
        assert_eq!(
            tree.get_children(1, 3),
            (tree.get_hash(0, 4), tree.get_hash(0, 5))
        );
    }

    #[test]
    fn equal_test_one_core_vs_few_cores() {
        let data = gen_data(1024, 8192);
        let tree_1 = MerkleTree::new(&data, num_cpus::get());
        let tree_2 = MerkleTree::new(&data, 1);
        assert_eq!(tree_1.get_root(), tree_2.get_root());
    }

}
