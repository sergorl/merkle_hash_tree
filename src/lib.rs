/// Merkle hash tree
/// 
/// # Examples
///
/// ```
/// use merkle_tree::MerkleTree;
/// use merkle_tree::to_hex_string;
/// use merkle_tree::gen_data;
///
/// let data = gen_data(8);
///
/// let tree = MerkleTree::new(&data, num_cpus::get());
///
/// println!("{}", tree);
/// println!("{}", to_hex_string(tree.get_root()));
///
/// ```

extern crate crossbeam;
extern crate crypto;
extern crate rand;

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
            panic!("Length of blocks shoul be greater ZERO!");
        } else {
            if blocks.iter().any(|block| block.len() < SIZE_BLOCK_HASH)  {
                panic!(
                    "Length of one or many blocks is less than min size of hash input {} bytes!",
                    SIZE_BLOCK_HASH
                );
            }
        }

        let levels = ((num_block + num_block % 2) as f64).log2().ceil() as usize;

        let mut hash_tree: Vec<Vec<u8>> = Vec::with_capacity(levels);

        create_base_tree(blocks, &mut hash_tree, num_cpus);

        for _ in 0..levels {
            create_and_fill_level(&mut hash_tree, num_cpus);
        }

        MerkleTree { tree: hash_tree }
    }

    pub fn get_root(&self) -> &[u8] {
        self.tree.last().unwrap().as_slice()
    }

    pub fn get_num_level(&self) -> usize {
        self.tree.len()
    }

    pub fn get_level(&self, index: usize) -> Option<&[u8]> {
        if index > self.tree.len() - 1 {
            None
        } else {
            Some(&self.tree[index])
        }
    }

    pub fn get_hash(&self, level: usize, index: usize) -> Option<&[u8]> {
        if level > self.tree.len() - 1 {
            None
        } else {
            let num_block = self.tree[level].len() / SIZE_BLOCK_HASH;
            if index > num_block {
                None
            } else {
                Some(&self.tree[level][index * SIZE_BLOCK_HASH..(index + 1) * SIZE_BLOCK_HASH])
            }
        }
    }

    pub fn get_parent(&self, level: usize, index: usize) -> Option<&[u8]> {
        if level + 1 > self.tree.len() - 1 {
            None
        } else {
            let num_block = self.tree[level + 1].len() / SIZE_BLOCK_HASH;
            let i = ((index as f64) / 2.0).floor() as usize;
            if i > num_block - 1 {
                None
            } else {
                Some(&self.tree[level + 1][i * SIZE_BLOCK_HASH..(i + 1) * SIZE_BLOCK_HASH])
            }
        }
    }

    pub fn get_children(&self, level: usize, index: usize) -> Option<(&[u8], &[u8])> {
        let levels = self.tree.len() - 1;
        if level > levels || level == 0 || levels == 0 {
            None
        } else {
            let num_block = self.tree[level - 1].len() / SIZE_BLOCK_HASH;
            let i = 2 * index;
            if i > num_block {
                None
            } else {
                Some((
                    &self.tree[level - 1][i * SIZE_BLOCK_HASH..(i + 1) * SIZE_BLOCK_HASH],
                    &self.tree[level - 1][(i + 1) * SIZE_BLOCK_HASH..(i + 2) * SIZE_BLOCK_HASH],
                ))
            }
        }
    }
}

/// Trait for display MerkleTree
impl fmt::Display for MerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut level: usize = 0;

        write!(f, "{}\n", "Tree: ");     

        for hash_level in &self.tree {
            write!(f, "Level {}: \n", level);                
            for hash in hash_level.chunks(SIZE_BLOCK_HASH) {
                write!(f, "{}\n", to_hex_string(hash));                
            }  
            level += 1; 
            write!(f, "{}\n", "-------------------------------------------------------------------------------------");          
        }

        write!(f, "{}", "End.")
    }
}

/// Convert array slice of u8 to string representation
pub fn to_hex_string(bytes: &[u8]) -> String {
    let strs: String = bytes.iter().map(|byte| format!("{:02X}", byte)).collect();
    strs
}

/// Hash = Sha256 for first stage of Hash function of Merkle Tree
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

/// Hash = Sha256 for base of hash tree
fn hash(data: &[u8], hashed: &mut [u8]) {
    let mut sha = Sha256::new();
    sha.input(data);
    sha.result(hashed);
}

/// Create vector of new level of hash tree
fn create_level(size: usize) -> Vec<u8> {
    let mut new_level: Vec<u8> = Vec::with_capacity(size);

    for _ in 0..size {
        new_level.push(0u8);
    }

    new_level
}

/// Copy data from source to destination by pointers to previous level of hash tree
fn copy_last_data(data: &mut Vec<u8>, num_block: usize) {
    let src = data.as_ptr();
    let dst = data.as_mut_ptr();

    unsafe {
        for i in (num_block - 2) * SIZE_BLOCK_HASH..(num_block - 1) * SIZE_BLOCK_HASH {
            *dst.offset((i + SIZE_BLOCK_HASH) as isize) = *src.offset(i as isize);
        }
    }
}

/// Create new level of hash tree
fn create_and_fill_level(hash_tree: &mut Vec<Vec<u8>>, num_cpus: usize) {

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

        for blocks in prev_level.chunks(num_cpus * SIZE_INPUT_HASH) {
            crossbeam::scope(|scope| {
                for (input, result) in blocks
                    .chunks(SIZE_INPUT_HASH)
                    .zip(new_level.chunks_mut(SIZE_BLOCK_HASH))
                {
                    scope.spawn(move || hash_hash(input, result));
                }
            });
        }

        if addition == 1 && num_block_in_prev_level > 2 {
            copy_last_data(&mut new_level, num_block_in_new_level);
        }
    }

    hash_tree.push(new_level);
}

/// Create base of hash tree and add this base to vector of hash levels in Merkle Tree
fn create_base_tree(blocks: &Vec<Vec<u8>>, hash_tree: &mut Vec<Vec<u8>>, num_cpus: usize) {
    let size = blocks.len();
    let num_block = size + size % 2;

    let mut base: Vec<u8> = create_level(num_block * SIZE_BLOCK_HASH);

    for block in blocks.chunks(num_cpus) {
        crossbeam::scope(|scope| {
            for (input, result) in block.iter().zip(base.chunks_mut(SIZE_BLOCK_HASH)) {
                scope.spawn(move || hash(input, result));
            }
        });
    }

    if size % 2 == 1 {
        copy_last_data(&mut base, num_block);
    }

    hash_tree.push(base);
}

/// Create random data
pub fn gen_data(capacity: usize) -> Vec<Vec<u8>> {
    let mut data: Vec<Vec<u8>> = Vec::with_capacity(capacity);

    let mut rng = rand::thread_rng();

    for _ in 0..capacity {
        let mut nums = [0u8; 32];
        for num in nums.iter_mut() {
            *num = rng.gen_range::<u8>(0, 255);
        }
        data.push(nums.to_vec());
    }

    data
}
