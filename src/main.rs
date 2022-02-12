use sha3::{Digest, Sha3_256};
use std::fmt::Write;
use std::fs;
use walkdir::WalkDir;

fn main() -> Result<(), std::fmt::Error> {
    for entry in WalkDir::new("test_data").sort_by_file_name().contents_first(true) {
        let entry = match entry {
            Ok(v) => v,
            Err(_) => continue,
        };
        println!("{}", entry.path().display());
    }
    Ok(())
}
