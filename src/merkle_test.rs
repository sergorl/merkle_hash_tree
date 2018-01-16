#![cfg_attr(feature = "unstable", feature(test))]


#[cfg(all(feature = "unstable", test))]
mod tests {

    extern crate test;
    extern crate rand;
    extern crate merkle_tree;

    use rand::Rng;
    use test::Bencher;
    use merkle_tree::MerkleTree;
    use merkle_tree::gen_data;

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

    
    #[bench]
    fn bench_one_core(b: &mut Bencher) {
        b.iter(|| {            
            MerkleTree::new(&gen_data(1024), 1)     
        });
    }

    #[bench]
    fn bench_few_core(b: &mut Bencher) {
        b.iter(|| {            
            MerkleTree::new(&gen_data(1024), 8)     
        });
    }
}


