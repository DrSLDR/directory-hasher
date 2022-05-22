use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs;
use walkdir::{DirEntry, WalkDir};

#[cfg(debug_assertions)]
use hex::encode;

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
    pub fn to_u8(self) -> u8 {
        match self {
            NodeType::Directory => 2,
            NodeType::DirSeparator => 3,
            NodeType::File => 5,
            NodeType::Symlink => 7,
        }
    }
}

/// Defines the different types of returns from [`hash_content`]
#[derive(Debug, Clone)]
enum ContentResult {
    /// A File result is any return that actually includes data, that is a regular file
    /// or a symlink, handled as needed.
    File(Vec<u8>),
    /// A Directory result is a signal that the node is a directory and queued node
    /// hashes need to be appended.
    Directory,
}

/// Defines the error states arising from hashing the content of a node
#[derive(Debug)]
pub enum ContentError {
    UnknownNodeType,
    IOError(std::io::Error),
}

impl fmt::Display for ContentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ContentError::UnknownNodeType => write!(f, "Node is not a directory, file, or symlink"),
            ContentError::IOError(_) => write!(f, "Encountered a problem opening a node"),
        }
    }
}

impl From<std::io::Error> for ContentError {
    fn from(err: std::io::Error) -> Self {
        Self::IOError(err)
    }
}

/// Error types from the [`hash_directory`] function
#[derive(Debug)]
pub enum HashError {
    ContentError(ContentError),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Hash could not be computed")
    }
}

impl From<ContentError> for HashError {
    fn from(err: ContentError) -> Self {
        Self::ContentError(err)
    }
}

/// Given a path to a directory, as a [`&str`], computes the directory hash and returns
/// it as a byte array.
///
/// # Examples
///
/// no
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
/// `hash(hash(name) + byte + hash(content))`
///
/// For **directories**, the node hash includes arbitrarily many content hashes, one per
/// sub-node:
/// `hash(hash(name) + byte + hash(content_1) + byte + hash(content_2) + ... + byte +
/// hash(content_n))`
///
/// Finally, for **symlinks**, the link isn't followed. Instead, the content hash is the
/// hash of the path to the file the link points to.
/// `hash(hash(name) + byte + hash(path))`
pub fn hash_directory(path: &str) -> Result<Vec<u8>, HashError> {
    let mut cache_map: HashMap<usize, VecDeque<Vec<u8>>> = HashMap::new();

    for entry in WalkDir::new(&path).sort_by_file_name().contents_first(true) {
        let entry = match entry {
            Ok(v) => v,
            Err(_) => continue,
        };

        println!("{}", entry.path().display());

        let content = hash_content(&entry)?;
        let name = Vec::from(
            Sha3_256::new()
                .chain_update(entry.file_name().to_string_lossy().as_bytes())
                .finalize()
                .as_slice(),
        );

        println!(
            "content: {:?}",
            match &content {
                crate::ContentResult::File(v) => hex::encode(&v),
                crate::ContentResult::Directory => "Directory".to_string(),
            }
        );
        println!("name: {:?}", hex::encode(&name));

        let node = match content {
            crate::ContentResult::File(content) => node_file_hash(&entry, name, content),
            crate::ContentResult::Directory => node_dir_hash(&mut cache_map, &entry, name),
        };

        println!("node: {:?}", hex::encode(&node));

        match cache_map.get_mut(&entry.depth()) {
            Some(q) => q.push_back(node),
            None => {
                let mut q: VecDeque<Vec<u8>> = VecDeque::new();
                q.push_back(node);
                cache_map.insert(entry.depth(), q);
            }
        }

        println!("map: {:?}", cache_map);
    }

    Ok(cache_map.get_mut(&0).unwrap().pop_front().unwrap())
}

/// Given a [`DirEntry`], hashes its contents according to the type of node.
fn hash_content(entry: &DirEntry) -> Result<ContentResult, ContentError> {
    if entry.file_type().is_symlink() {
        Ok(ContentResult::File(Vec::from(
            Sha3_256::new()
                .chain_update(fs::read_link(entry.path())?.to_string_lossy().as_bytes())
                .finalize()
                .as_slice(),
        )))
    } else if entry.file_type().is_dir() {
        Ok(ContentResult::Directory)
    } else if entry.file_type().is_file() {
        Ok(ContentResult::File(Vec::from(
            Sha3_256::new()
                .chain_update(fs::read(entry.path())?)
                .finalize()
                .as_slice(),
        )))
    } else {
        Err(ContentError::UnknownNodeType)
    }
}

/// Generates the node hash of a given File node
fn node_file_hash(entry: &DirEntry, name: Vec<u8>, content: Vec<u8>) -> Vec<u8> {
    Vec::from(
        Sha3_256::new()
            .chain_update(name)
            .chain_update(if entry.file_type().is_symlink() {
                [NodeType::Symlink.to_u8()]
            } else {
                [NodeType::File.to_u8()]
            })
            .chain_update(content)
            .finalize()
            .as_slice(),
    )
}

/// Generates the node hash of a given Directory node
fn node_dir_hash(
    cache: &mut HashMap<usize, VecDeque<Vec<u8>>>,
    entry: &DirEntry,
    name: Vec<u8>,
) -> Vec<u8> {
    let mut hasher = Sha3_256::new()
        .chain_update(name)
        .chain_update([NodeType::Directory.to_u8()]);
    let mut first: bool = true;
    let q = cache.get_mut(&(entry.depth() + 1)).unwrap();
    for node in q.iter() {
        if !first {
            hasher.update([NodeType::DirSeparator.to_u8()]);
        } else {
            first = false;
        }
        hasher.update(node);
    }
    q.clear();
    Vec::from(hasher.finalize().as_slice())
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
        // one.test content: 9241024260f87e2b901ed6972c48a17c4dc71e0939b0dd445f431f9cf406ca3a
        // one.test name:    8d80e5830940407463f61fe1ef751de17cb095f8646ff71a72b1374efe5d84c5
        // one.test node:    7716a22d94ecef97998c296ec7914ee0f6bcd66d8b37ac82688b4a3a4ba0a0ca
        // one name:         6f70f27e13fc073a2541cd1e8b38ba9dbd5ec6de7bfeb24328534c417697381f
        // one node:         9fd3dceb108e5f6067a623a592524a4014f5d7244e537891d147b51e8c1c147d
        let result = crate::hash_directory("test_data/one").unwrap();
        assert_eq!(
            result[..],
            hex!("9fd3dceb108e5f6067a623a592524a4014f5d7244e537891d147b51e8c1c147d")
        )
    }

    #[test]
    fn hash_test_data_two() {
        // one.test content: 9241024260f87e2b901ed6972c48a17c4dc71e0939b0dd445f431f9cf406ca3a
        // one.test name:    8d80e5830940407463f61fe1ef751de17cb095f8646ff71a72b1374efe5d84c5
        // one.test node:    7716a22d94ecef97998c296ec7914ee0f6bcd66d8b37ac82688b4a3a4ba0a0ca
        // two.test content: f2ee51400cb7890e88835039d97b3411df6d2460843c8e84b3f7541c40eec1ba
        // two.test name:    af148b4b830b9882103cf3ca767e34a6e4dc52a0b6f08df31a77ae9903d1949d
        // two.test node:    a6e7380dabe9ba94240a56570ba58dc457e57924ad78bc2476867dcbfd57c8eb
        // subone name:      55fc1f2b086b1f8bde1078ae015e788ec2766e38f68a19deedc1d4cc1a882a57
        // subone node:      2c57a0604a04b43168f02b177d6ac0f0205c70c1896a6c0b4eefd870dfe7089d
        // bacon.test cont:  5d9121bfbe2ccd96c4e2e94e2c0c4a9940fb325f728fd5de26fc3e0f8df37914
        // bacon.test name:  e176fb76eb3d39d67764c86a91dfb5ff11ce95ae556145bef4112434da0cffcf
        // bacon.test node:  0ffcbf39480556cf4438cbe5bd18b926d9abecb8f1ea99f75d31f28a84429c8d
        // two.test(l) cont: 29077be8b7ce3922951fb75ff84cf5aa29edbddd86725ee7b34a4508345b93a5
        // two.test(l) node: b97f5177d45d1cac7b7b381609684fe2c689f8538bcc92db0a8312a0c6b83185
        // subtwo name:      996340b04c5f9afc98dc7b81278eff5e796a814c6078101391277461246cc5b7
        // subtwo node:      fa44844774f5f9e126e5a8d6b3c426b1f8b9af9abf7984371fae9ff4ef57e305
        // two name:         cad32d6da454536a0412369e78baf227a81309b9579df2f450d1b5f5c8c26bf0
        // two node:         9119ffd015d217097164f944331ee865fb6ac8c0b670728cf42c9e45c21ea0df
        let result = crate::hash_directory("test_data/two").unwrap();
        assert_eq!(
            result[..],
            hex!("9119ffd015d217097164f944331ee865fb6ac8c0b670728cf42c9e45c21ea0df")
        )
    }

    #[test]
    fn hash_test_data_all() {
        // one node:         9fd3dceb108e5f6067a623a592524a4014f5d7244e537891d147b51e8c1c147d
        // two node:         9119ffd015d217097164f944331ee865fb6ac8c0b670728cf42c9e45c21ea0df
        // test_data name:   d9c66fed039088497293a5155e68c9722336edef5991a67fa285d9a2565582bf
        // test_data node:   3b5e49ac9126759771d677bdacbc18a63ff94ad4e07718c18347254d7b9c6cb1
        let result = crate::hash_directory("test_data").unwrap();
        assert_eq!(
            result[..],
            hex!("3b5e49ac9126759771d677bdacbc18a63ff94ad4e07718c18347254d7b9c6cb1")
        )
    }
}
