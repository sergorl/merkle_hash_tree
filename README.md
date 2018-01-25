# merkle_hash_tree
Rust implementation of [merkle hash tree](https://en.wikipedia.org/wiki/Merkle_tree)
![scheme of Merkle hash tree](https://github.com/sergorl/merkle_hash_tree/blob/master/merkle_tree_description.png)


### Dependencies

- [Rayon](https://crates.io/crates/rayon) is used to parallelize of hash function and TRY to speed up performance.
- [Rust-Crypto](https://crates.io/crates/rust-crypto) is used to applying hash function (sha256).
- [rand](https://crates.io/crates/rand) is used to create test data.

### Advantages

- Easy-to-use api
- Ability to run parallel calculations of hash function

### Lacks

- Size of input byte block for hash function should be not less than 32. It is feature of [crypto::sha2::Sha256](https://docs.rs/rust-crypto/0.2.36/crypto/sha2/struct.Sha256.html).
- There is no possibility to use another hash function. May be in the future will add feature to apply any hash function.
