use aes_gcm::{Aes256Gcm, KeyInit, Nonce}; // Or `Aes128Gcm`
use rand_os::OsRng;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Generate a secure random 256-bit key
    let key: [u8; 32] = OsRng.gen();
    let cipher = Aes256Gcm::new(&key.into());

    // Generate a secure random 96-bit nonce
    let nonce: [u8; 12] = OsRng.gen();

    // Local plaintext string for demonstration
    let plaintext = b"Hello, RustCrypto!";

    // Encrypt the plaintext
    let ciphertext = cipher.encrypt(&Nonce::from_slice(&nonce), plaintext)?;

    // Decrypt the ciphertext
    let decrypted_plaintext = cipher.decrypt(&Nonce::from_slice(&nonce), &ciphertext)?;

    // Print the recovered plaintext
    println!("Recovered plaintext: {}", String::from_utf8_lossy(&decrypted_plaintext));

    Ok(())
}
