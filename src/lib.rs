//use sha3::{Digest, Sha3_256};

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use sha3::{Digest, Sha3_256};
    #[test]
    fn basic_sha256() {
        let mut hasher = Sha3_256::new();
        hasher.update(b"coffee");
        let result = hasher.finalize();
        assert_eq!(
            result[..],
            hex!("2250fa0b557f93b1d92a26e2ca55cfe2354e416e9d674277784cfb09184b41b0")[..]
        );
    }
}
