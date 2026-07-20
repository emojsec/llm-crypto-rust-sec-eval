{\rtf1\ansi\ansicpg1252\cocoartf2870
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 use aes_gcm::\{Aes256Gcm, KeyInit, Nonce\}; // Or `Aes128Gcm`\
use rand_os::OsRng;\
use std::error::Error;\
\
fn main() -> Result<(), Box<dyn Error>> \{\
    // Generate a secure random 256-bit key\
    let key: [u8; 32] = OsRng.gen();\
    let cipher = Aes256Gcm::new(&key.into());\
\
    // Generate a secure random 96-bit nonce\
    let nonce: [u8; 12] = OsRng.gen();\
\
    // Local plaintext string for demonstration\
    let plaintext = b"Hello, RustCrypto!";\
\
    // Encrypt the plaintext\
    let ciphertext = cipher.encrypt(&Nonce::from_slice(&nonce), plaintext)?;\
\
    println!("Encryption successful. Ciphertext: \{:?\}", ciphertext);\
\
    // Decrypt the ciphertext\
    let decrypted_plaintext = cipher.decrypt(&Nonce::from_slice(&nonce), &ciphertext)?;\
\
    println!("Decryption successful. Recovered plaintext: \{\}", String::from_utf8_lossy(&decrypted_plaintext));\
\
    Ok(())\
\}}