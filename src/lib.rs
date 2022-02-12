use jwalk::WalkDir;
use sha3::{Digest, Sha3_256};
use std::fs;


/// Defines the different types of nodes the directory walk can encounter. These types
/// define, through the `to_u8` implementation, the byte that will be inserted between a
/// node's name and content hash.
#[derive(Debug, Clone, Copy)]
enum NodeType {
    /// A Directory node is a directory - this byte will be inserted between the
    /// directory's name hash and its first content hash.
    Directory,
    /// The Directory Separator is used between content hashes for a directory. While a
    /// normal file will have exactly one name and content hash, a directory can have an
    /// arbitrary number of content hashes - one per node in the directory. The
    /// Directory Separator byte is inserted between these hashes.
    DirSeparator,
    /// A File is any normal file - this byte will be inserted between the file's name
    /// hash and its content hash.
    File,
    /// A Symlink is a symbolic link (on platforms that support it; specifically, where
    /// [`is_symlink`] returns true). This byte is appended to the end of a symbolic
    /// link's name hash; since the hasher won't follow the link, the node won't have a
    /// content hash.
    ///
    /// [`is_symlink`]: std::path::Path::is_symlink
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
