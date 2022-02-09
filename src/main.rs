use jwalk::WalkDir;
use sha3::{Digest, Sha3_256};
use std::fmt::Write;

fn main() -> Result<(), std::fmt::Error> {
    for entry in WalkDir::new("test_data").sort(true) {
        let mut hasher = Sha3_256::new();
        let de = entry.unwrap();
        hasher.update(&de.path().as_path().to_str().unwrap());
        let value = hasher.finalize();
        let mut hexv = String::with_capacity(2 * value.len());
        for byte in value {
            write!(hexv, "{:02x}", byte)?;
        }
        println!("{}", &de.path().display());
        println!("{}", hexv);
    }
    Ok(())
}
