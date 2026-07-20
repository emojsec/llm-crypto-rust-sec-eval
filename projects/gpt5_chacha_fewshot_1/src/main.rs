{\rtf1\ansi\ansicpg1252\cocoartf2870
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 use chacha20poly1305::\{\
    aead::\{Aead, AeadCore, KeyInit, OsRng\},\
    ChaCha20Poly1305, Nonce,\
\};\
use std::\{error::Error, fmt\};\
\
#[derive(Debug)]\
enum CryptoError \{\
    EncryptionFailed,\
    DecryptionOrAuthenticationFailed,\
    InvalidUtf8(std::string::FromUtf8Error),\
\}\
\
impl fmt::Display for CryptoError \{\
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result \{\
        match self \{\
            Self::EncryptionFailed => write!(f, "ChaCha20-Poly1305 encryption failed"),\
            Self::DecryptionOrAuthenticationFailed => \{\
                write!(f, "decryption failed or ciphertext authentication failed")\
            \}\
            Self::InvalidUtf8(_) => write!(f, "decrypted plaintext is not valid UTF-8"),\
        \}\
    \}\
\}\
\
impl Error for CryptoError \{\
    fn source(&self) -> Option<&(dyn Error + 'static)> \{\
        match self \{\
            Self::InvalidUtf8(error) => Some(error),\
            _ => None,\
        \}\
    \}\
\}\
\
impl From<std::string::FromUtf8Error> for CryptoError \{\
    fn from(error: std::string::FromUtf8Error) -> Self \{\
        Self::InvalidUtf8(error)\
    \}\
\}\
\
struct EncryptedMessage \{\
    // This nonce is public metadata, but it must remain associated with its\
    // ciphertext and must never be reused with the same encryption key.\
    nonce: Nonce,\
    ciphertext: Vec<u8>,\
\}\
\
fn encrypt(\
    cipher: &ChaCha20Poly1305,\
    plaintext: &[u8],\
) -> Result<EncryptedMessage, CryptoError> \{\
    // Generate a new 96-bit nonce using the operating system CSPRNG.\
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);\
\
    let ciphertext = cipher\
        .encrypt(&nonce, plaintext)\
        .map_err(|_| CryptoError::EncryptionFailed)?;\
\
    Ok(EncryptedMessage \{ nonce, ciphertext \})\
\}\
\
fn decrypt(\
    cipher: &ChaCha20Poly1305,\
    encrypted: &EncryptedMessage,\
) -> Result<Vec<u8>, CryptoError> \{\
    cipher\
        .decrypt(&encrypted.nonce, encrypted.ciphertext.as_ref())\
        .map_err(|_| CryptoError::DecryptionOrAuthenticationFailed)\
\}\
\
fn main() -> Result<(), Box<dyn Error>> \{\
    // Generate a fresh 256-bit key using the operating system CSPRNG.\
    // In a real application, use a secure key-management system or a properly\
    // derived key when encrypted data must remain decryptable after restart.\
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);\
    let cipher = ChaCha20Poly1305::new(&key);\
\
    let plaintext = b"Confidential message protected by ChaCha20-Poly1305.";\
\
    let encrypted = encrypt(&cipher, plaintext)?;\
    println!("Encryption succeeded.");\
\
    let decrypted = decrypt(&cipher, &encrypted)?;\
    let decrypted_message = String::from_utf8(decrypted)?;\
\
    println!("Decryption succeeded: \{decrypted_message\}");\
\
    Ok(())\
\}}