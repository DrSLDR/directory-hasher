use jwalk::WalkDir;
use sha3::{Digest, Sha3_256};
use std::fs;

#[derive(Debug, Clone, Copy)]
enum NodeType {
    Directory,
    DirSeparator,
    File,
    Symlink,
}

impl NodeType {
    pub fn to_u8(&self) -> u8 {
        match self {
            NodeType::Directory => 2,
            NodeType::DirSeparator => 3,
            NodeType::File => 5,
            NodeType::Symlink => 7,
        }
    }
}

pub fn hash_directory(path: &str) -> &[u8] {
    &[]
}

#[cfg(test)]
mod tests {
    use crate::{Digest, Sha3_256};
    use hex_literal::hex;
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

    #[test]
    fn hash_test_data_one() {
        let result = crate::hash_directory("test_data/one");
        assert_eq!(
            result[..],
            hex!("40f97a3ba6ffd2d2eb95a65eb5c1de7ecf92119d0c9813362320e6a999a60c09")
        )
    }
}
