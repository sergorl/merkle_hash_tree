//! Merkle hash tree - binary tree which consists of two or more levels
//! Each tree level is a vector of bytes which is a result of applying hash function to previous level
//! Tree level indexing starts with zero: zero level is a result of applying hash function to input byte blocks
//!                                       last (or max) level is a root of tree
//! Zero level is formed of input byte blocks. If number of block is odd then last block is copy. It is also true for other tree levels (exception is root)
//! Thus, the length of each tree level (exception is root) is always even
//!
//! The used hash function is sha256(...) for zero level and hash_hash = sha256(sha256(...)) for other levels.
//! The length of sha256 input should be not less than constant SIZE_BLOCK_HASH. It is necessary for crate crypto
//! The length of hash_hash input should be not less than constant SIZE_INPUT_HASH = 2 * SIZE_BLOCK_HASH. It is necessary for Merkle tree
//!
//! Tree level is a vector of contiguous batch of hash bytes which size is SIZE_BLOCK_HASH
//! Thus, each level contains (number of blocks * SIZE_BLOCK_HASH) hash bytes
//!
//! # Example
//! ```rust,ignore
//!
//! extern crate merkle_tree;
//! use merkle_tree::MerkleTree;
//! use merkle_tree::to_hex_string;
//!
//! let data: Vec<Vec<u8>> = vec![vec![0u8; 32], vec![0u8; 32]]; // or let data = gen_data(2, 32);
//! let mtree = MerkleTree::new(&data, 1); // second parameter is number of cpu cores
//! let root: String = to_hex_string(mtree.get_root());
//! ```
//!

extern crate crypto;
extern crate rand;
extern crate rayon;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::vec::Vec;
use rand::Rng;
use std::fmt;

const SIZE_INPUT_HASH: usize = 64;
const SIZE_BLOCK_HASH: usize = 32;

pub struct MerkleTree {
    tree: Vec<Vec<u8>>,
}

impl MerkleTree {
    pub fn new(blocks: &Vec<Vec<u8>>, num_cpus: usize) -> MerkleTree {
        let num_block = blocks.len();

        if num_block == 0 {
            panic!("Length of blocks should be greater ZERO!");
        } else {
            use rayon::prelude::*;
            if blocks.par_iter().any(|block| block.len() < SIZE_BLOCK_HASH) {
                panic!(
                    "Length of one or many blocks is less than min size of hash input {} bytes!",
                    SIZE_BLOCK_HASH
                );
            }
        }

        // Pool of thread to speed up calculations of hash function for the current tree level
        let pool =
            rayon::ThreadPool::new(rayon::Configuration::new().num_threads(num_cpus)).unwrap();

        let levels = ((num_block + num_block % 2) as f64).log2().ceil() as usize;

        // Merkle tree - vector of tree levels, where each level is vector of hash bytes
        let mut hash_tree: Vec<Vec<u8>> = Vec::with_capacity(levels);

        // At first, create a zero level applying sha256(...) to each input block of bytes
        create_hash_zero_level(blocks, &mut hash_tree, &pool, num_cpus);

        for _ in 0..levels {
            // Then create other levels
            create_hash_level(&mut hash_tree, &pool, num_cpus);
        }

        MerkleTree { tree: hash_tree }
    }

    pub fn get_root(&self) -> &[u8] {
        self.tree.last().unwrap().as_slice()
    }

    pub fn get_num_level(&self) -> usize {
        self.tree.len()
    }

    pub fn get_level(&self, index: usize) -> &[u8] {
        if index > self.tree.len() - 1 {
            panic!("Invalid index in get_level()!");
        } else {
            &self.tree[index]
        }
    }

    pub fn get_hash(&self, level: usize, index: usize) -> &[u8] {
        if level > self.tree.len() - 1 {
            panic!("Invalid level in get_hash()!");
        } else {
            let num_block = self.tree[level].len() / SIZE_BLOCK_HASH;

            if index > num_block - 1 {
                panic!("Invalid index in get_hash()!");
            } else {
                &self.tree[level][index * SIZE_BLOCK_HASH..(index + 1) * SIZE_BLOCK_HASH]
            }
        }
    }

    pub fn get_parent(&self, level: usize, index: usize) -> &[u8] {
        if level + 1 > self.tree.len() - 1 {
            panic!("Invalid level in get_parent()!");
        } else {
            let num_block = self.tree[level + 1].len() / SIZE_BLOCK_HASH;
            let i = ((index as f64) / 2.0).floor() as usize;

            if i > num_block - 1 {
                panic!("Invalid index in get_parent()!");
            } else {
                &self.tree[level + 1][i * SIZE_BLOCK_HASH..(i + 1) * SIZE_BLOCK_HASH]
            }
        }
    }

    pub fn get_children(&self, level: usize, index: usize) -> (&[u8], &[u8]) {
        let levels = self.tree.len();
        if level > levels - 1 || level == 0 {
            panic!("Invalid level in get_children()!");
        } else {
            let num_block = self.tree[level - 1].len() / SIZE_BLOCK_HASH;
            let mut i = 2 * index;

            // for blocks which don't have children because
            // it was build by copy last block of previous level with odd number of blocks
            if i == num_block {
                i = num_block - 2;
            }

            if i > num_block - 1 {
                panic!("Invalid index in get_children()!");
            } else {
                (
                    &self.tree[level - 1][i * SIZE_BLOCK_HASH..(i + 1) * SIZE_BLOCK_HASH],
                    &self.tree[level - 1][(i + 1) * SIZE_BLOCK_HASH..(i + 2) * SIZE_BLOCK_HASH],
                )
            }
        }
    }
}

/// Trait for display MerkleTree
impl fmt::Display for MerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut level: usize = 0;
        let mut index: usize = 0;

        write!(f, "{}\n", "Tree: ");

        for hash_level in &self.tree {
            write!(f, "Level {}: \n", level);

            for hash in hash_level.chunks(SIZE_BLOCK_HASH) {
                write!(f, "hash {}: {}\n", index, to_hex_string(hash));
                index += 1;
            }

            index = 0;
            level += 1;
            write!(
                f,
                "{}\n",
                "--------------------------------------------------------------------"
            );
        }

        Ok(())
    }
}

/// Convert array slice of u8 to string representation
pub fn to_hex_string(bytes: &[u8]) -> String {
    let strs: String = bytes.iter().map(|byte| format!("{:02X}", byte)).collect();
    strs
}

/// Hash = Sha256 for first stage of hash function
fn hash_1(data: &[u8]) -> (Vec<u8>, Sha256) {
    let mut sha = Sha256::new();

    let mut hashed: Vec<u8> = Vec::with_capacity(SIZE_BLOCK_HASH);

    for _ in 0..SIZE_BLOCK_HASH {
        hashed.push(0u8);
    }

    sha.input(data);
    sha.result(hashed.as_mut_slice());
    sha.reset();

    (hashed, sha)
}

/// Hash = Sha256(Sha256())
fn hash_hash(data: &[u8], hashed: &mut [u8]) {
    let (data, mut sha) = hash_1(data);
    sha.input(data.as_slice());
    sha.result(hashed);
}

/// Hash = Sha256 for zero hash level
fn hash(data: &[u8], hashed: &mut [u8]) {
    let mut sha = Sha256::new();
    sha.input(data);
    sha.result(hashed);
}

/// Allocate vector with necessary capacity. It creates blueprint of new tree level
fn create_level(size: usize) -> Vec<u8> {
    let mut new_level: Vec<u8> = Vec::with_capacity(size);

    for _ in 0..size {
        new_level.push(0u8);
    }

    new_level
}

/// Copy data from source to destination by pointers (of previous tree level)
/// It is used if previous level contains an odd number of byte block
fn copy_last_data(data: &mut Vec<u8>, num_block: usize) {
    let src = data.as_ptr();
    let dst = data.as_mut_ptr();

    unsafe {
        for i in (num_block - 2) * SIZE_BLOCK_HASH..(num_block - 1) * SIZE_BLOCK_HASH {
            *dst.offset((i + SIZE_BLOCK_HASH) as isize) = *src.offset(i as isize);
        }
    }
}

/// Parallel hash for tree levels (exception is zero level, it has own function)
fn par_hash_hash(prev_level: &Vec<u8>, new_level: &mut Vec<u8>, pool: &rayon::ThreadPool) {
    pool.scope(|scope| {
        for (input, result) in prev_level
            .chunks(SIZE_INPUT_HASH)
            .zip(new_level.chunks_mut(SIZE_INPUT_HASH))
        {
            scope.spawn(move |_| hash_hash(input, result));
        }
    });
}

/// Create new level and add it to vector of tree hash levels
fn create_hash_level(hash_tree: &mut Vec<Vec<u8>>, pool: &rayon::ThreadPool, num_cpus: usize) {
    let size_prev_level: usize = hash_tree.last().unwrap().len();

    let num_block_in_prev_level = size_prev_level / SIZE_BLOCK_HASH;
    let addition = (num_block_in_prev_level / 2) % 2;
    let num_block_in_new_level: usize;

    if num_block_in_prev_level > 2 {
        num_block_in_new_level = num_block_in_prev_level / 2 + addition;
    } else {
        num_block_in_new_level = 1;
    }

    let mut new_level = create_level(num_block_in_new_level * SIZE_BLOCK_HASH);

    {
        let prev_level = hash_tree.last().unwrap();
        let num_thread: usize;

        if pool.current_num_threads() > num_block_in_new_level {
            let pool = rayon::ThreadPool::new(
                rayon::Configuration::new().num_threads(num_block_in_new_level),
            ).unwrap();
            par_hash_hash(&prev_level, &mut new_level, &pool);
        } else {
            par_hash_hash(&prev_level, &mut new_level, &pool);
        }
    }

    if addition == 1 && num_block_in_prev_level > 2 {
        copy_last_data(&mut new_level, num_block_in_new_level);
    }

    hash_tree.push(new_level);
}

/// Parallel hash for zero level
fn par_zero_hash(blocks: &Vec<Vec<u8>>, base: &mut Vec<u8>, pool: &rayon::ThreadPool) {
    pool.scope(|scope| {
        for (input, result) in blocks.iter().zip(base.chunks_mut(SIZE_INPUT_HASH)) {
            scope.spawn(move |_| hash(input, result));
        }
    });
}

/// Create zero level and add it to vector of tree hash levels
fn create_hash_zero_level(
    blocks: &Vec<Vec<u8>>,
    hash_tree: &mut Vec<Vec<u8>>,
    pool: &rayon::ThreadPool,
    num_cpus: usize,
) {
    let size = blocks.len();
    let num_block = size + size % 2;

    let mut base: Vec<u8> = create_level(num_block * SIZE_BLOCK_HASH);

    if pool.current_num_threads() > num_block {
        let pool =
            rayon::ThreadPool::new(rayon::Configuration::new().num_threads(num_block)).unwrap();

        par_zero_hash(&blocks, &mut base, &pool);
    } else {
        par_zero_hash(&blocks, &mut base, &pool);
    }

    if size % 2 == 1 {
        copy_last_data(&mut base, num_block);
    }

    hash_tree.push(base);
}

/// Create random data - vector of byte blocks with fixed size
pub fn gen_data(num_block: usize, size_block: usize) -> Vec<Vec<u8>> {
    let mut data: Vec<Vec<u8>> = Vec::with_capacity(num_block);

    let mut rng = rand::thread_rng();

    for _ in 0..num_block {
        let mut block: Vec<u8> = Vec::with_capacity(size_block);
        for _ in 0..size_block {
            block.push(rng.gen_range::<u8>(0, 255));
        }
        data.push(block);
    }

    data
}
