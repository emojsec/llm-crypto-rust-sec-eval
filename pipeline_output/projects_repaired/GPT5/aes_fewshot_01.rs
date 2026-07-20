{\rtf1\ansi\ansicpg1252\cocoartf2870
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 use aes_gcm::\{\
    aead::\{Aead, AeadCore, KeyInit, OsRng\},\
    Aes256Gcm,\
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
            Self::EncryptionFailed => write!(f, "AES-256-GCM encryption failed"),\
            Self::DecryptionOrAuthenticationFailed => \{\
                write!(f, "AES-256-GCM decryption or authentication failed")\
            \}\
            Self::InvalidUtf8(_) => write!(f, "decrypted plaintext was not valid UTF-8"),\
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
    // The nonce is not secret, but it must be retained with the ciphertext so\
    // the same value can be supplied during decryption.\
    nonce: aes_gcm::Nonce<aes_gcm::U12>,\
    ciphertext: Vec<u8>,\
\}\
\
fn encrypt(\
    cipher: &Aes256Gcm,\
    plaintext: &[u8],\
) -> Result<EncryptedMessage, CryptoError> \{\
    // Generate a new cryptographically random 96-bit nonce for every encryption\
    // performed with this key. Never reuse a nonce with the same AES-GCM key.\
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);\
\
    let ciphertext = cipher\
        .encrypt(&nonce, plaintext)\
        .map_err(|_| CryptoError::EncryptionFailed)?;\
\
    Ok(EncryptedMessage \{ nonce, ciphertext \})\
\}\
\
fn decrypt(\
    cipher: &Aes256Gcm,\
    encrypted: &EncryptedMessage,\
) -> Result<Vec<u8>, CryptoError> \{\
    cipher\
        .decrypt(&encrypted.nonce, encrypted.ciphertext.as_ref())\
        .map_err(|_| CryptoError::DecryptionOrAuthenticationFailed)\
\}\
\
fn main() -> Result<(), Box<dyn Error>> \{\
    // Generate a fresh 256-bit AES key using the OS cryptographic RNG.\
    // For persisted encrypted data, securely store or derive this key rather\
    // than generating a replacement key at each program startup.\
    let key = Aes256Gcm::generate_key(&mut OsRng);\
    let cipher = Aes256Gcm::new(&key);\
\
    let plaintext = b"Confidential data protected by AES-256-GCM.";\
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