use walkdir::WalkDir;
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
    /// [`is_symlink`] returns true). This byte is used instead of [`NodeType::File`]
    /// when the node is a symlink.
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

/// Given a path to a directory, as a [`&str`], computes the directory hash and returns
/// it as a byte array.
///
/// # Examples
///
/// ```
/// no, none of those
/// ```
///
/// # Scheme
///
/// The hashing scheme is, in essence, generating a [Merkle
/// tree](https://en.wikipedia.org/wiki/Merkle_tree), but with extra steps. Each node in
/// the directory tree has its name hashed, then its contents, then those hashes are
/// concatenated with a separator byte based on the node's type, and that data is hashed
/// again to generate the node's hash. This process is repeated, from the bottom up in
/// the directory tree, until all nodes have been hashed and a final hash for the entire
/// directory can be returned.
///
/// For normal **files**, the node hash is simply:
/// ```
/// hash(hash(name) + byte + hash(content))
/// ```
///
/// For **directories**, the node hash includes arbitrarily many content hashes, one per
/// sub-node:
/// ```
/// hash(hash(name) + byte + hash(content_1) + byte + hash(content_2) + ... + byte + hash(content_n))
/// ```
///
/// Finally, for **symlinks**, the link isn't followed. Instead, the content hash is the
/// hash of the path to the file the link points to.
/// ```
/// hash(hash(name) + byte + hash(path))
/// ```
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
