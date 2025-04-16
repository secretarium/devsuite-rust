use sha2::{Sha256, Digest};
use num_bigint::BigUint;
use rand::RngCore;

pub fn get_sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn increment_by(src: &[u8], offset: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if src.len() != offset.len() {
        return Err("Source and offset must be of the same length".into());
    }

    let src_bigint = BigUint::from_bytes_be(src);
    let offset_bigint = BigUint::from_bytes_be(offset);

    let result_bigint = src_bigint + offset_bigint;
    let result_bytes = result_bigint.to_bytes_be();
    //Pad with prefix 0s the result to the same length as the source
    let result = if result_bytes.len() < src.len() {
        let mut padded_result = vec![0u8; src.len() - result_bytes.len()];
        padded_result.extend(result_bytes);
        padded_result
    } else if result_bytes.len() > src.len() {
        result_bytes[result_bytes.len() - src.len()..].to_vec()
    } else {
        result_bytes
    };
    Ok(result)
}

pub fn get_random_bytes(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut buffer = vec![0u8; size];
    rng.fill_bytes(&mut buffer);
    buffer
}

pub fn pointwise_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Vectors must be of the same length");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_sha256_bytes() {
        let data = b"Hello, world!";
        let hash = get_sha256_bytes(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_increment_by_4() {
        let src = [0,1,2,3].as_slice();
        let offset = [0,1,2,3].as_slice();
        let result = increment_by(src, offset).unwrap();
        assert_eq!(result, [0,2,4,6]);
    }

    #[test]
    fn test_increment_by_16() {
        let src = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15].as_slice();
        let offset = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15].as_slice();
        let result = increment_by(src, offset).unwrap();
        assert_eq!(result, [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30]);
    }

    #[test]
    fn test_increment_by_16_offset_min() {
        let src = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15].as_slice();
        let offset = [0; 16].as_slice();
        let result = increment_by(src, offset).unwrap();
        assert_eq!(result, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn test_increment_by_16_offset_max_first_two() {
        let src = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15].as_slice();
        let offset = [255,255,2,3,4,5,6,7,8,9,10,11,12,13,14,15].as_slice();
        let result = increment_by(src, offset).unwrap();
        assert_eq!(result, [0, 0, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30]);
    }  

    #[test]
    fn test_increment_by_16_offset_max() {
        let src = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15].as_slice();
        let offset = [255; 16].as_slice();
        let result = increment_by(src, offset).unwrap();
        assert_eq!(result, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 14]);
    }    

    #[test]
    fn test_increment_by_16_src_min() {
        let src = [0; 16].as_slice();
        let offset = [0; 16].as_slice();
        let result = increment_by(src, offset).unwrap();
        assert_eq!(result, [0; 16]);
    }

    #[test]
    fn test_increment_by_16_src_max() {
        let src = [255; 16].as_slice();
        let offset = [0; 16].as_slice();
        let result = increment_by(src, offset).unwrap();
        assert_eq!(result, [255; 16]);
    }

    #[test]
    fn test_increment_by_16_src_random_offset_random() {
        for _ in 0..100 {
            let src = get_random_bytes(16);
            let offset = get_random_bytes(16);
            let result = increment_by(&src, &offset).unwrap();
            if result.len() != 16 {
                println!("Result length is not 16: {}", result.len());
            }
        }
    }

    #[test]
    fn test_get_random_bytes() {
        let size = 16;
        let random_bytes = get_random_bytes(size);
        assert_eq!(random_bytes.len(), size);
    }

    #[test]
    fn test_pointwise_xor() {
        let a = b"Hello, world!";
        let b = b"Hello, world!";
        let result = pointwise_xor(a, b);
        assert_eq!(result, vec![0; a.len()]);
    }
}