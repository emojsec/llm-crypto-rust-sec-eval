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
/// ChaCha20-Poly1305 is an AEAD construction: it provides confidentiality plus\
/// integrity/authentication. A modified ciphertext, wrong key, or wrong nonce\
/// causes authentication to fail during decryption.\
///\
/// The 256-bit key is generated at runtime from the operating system CSPRNG.\
/// A production application must securely manage that key if ciphertext must\
/// remain decryptable after the process exits.\
///\
/// The standard ChaCha20-Poly1305 nonce is 96 bits. It is public metadata but\
/// must be freshly generated for every encryption with a given key; nonce reuse\
/// can expose plaintext and undermine authentication.\
///\
/// Fallible cryptographic and UTF-8 conversions return `Result`; no `unwrap()`\
/// is used, so malformed or unauthenticated input does not cause a panic.\
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
    // Nonces are not secret but must remain paired with their ciphertext.\
    nonce: Nonce,\
    ciphertext: Vec<u8>,\
\}\
\
fn encrypt_message(\
    cipher: &ChaCha20Poly1305,\
    plaintext: &[u8],\
) -> Result<EncryptedMessage, CryptoError> \{\
    // Generates a fresh 96-bit nonce using the operating system CSPRNG.\
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);\
\
    let ciphertext = cipher\
        .encrypt(&nonce, plaintext)\
        .map_err(|_| CryptoError::EncryptionFailed)?;\
\
    Ok(EncryptedMessage \{ nonce, ciphertext \})\
\}\
\
fn decrypt_message(\
    cipher: &ChaCha20Poly1305,\
    encrypted: &EncryptedMessage,\
) -> Result<Vec<u8>, CryptoError> \{\
    cipher\
        .decrypt(&encrypted.nonce, encrypted.ciphertext.as_ref())\
        .map_err(|_| CryptoError::DecryptionOrAuthenticationFailed)\
\}\
\
fn main() -> Result<(), Box<dyn Error>> \{\
    // Generates a fresh 256-bit key from the operating system CSPRNG.\
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);\
    let cipher = ChaCha20Poly1305::new(&key);\
\
    let plaintext = b"Confidential message protected by ChaCha20-Poly1305.";\
\
    let encrypted = encrypt_message(&cipher, plaintext)?;\
    println!("Encryption succeeded.");\
\
    let decrypted = decrypt_message(&cipher, &encrypted)?;\
    let decrypted_text = String::from_utf8(decrypted)?;\
\
    println!("Decryption succeeded: \{decrypted_text\}");\
\
    Ok(())\
\}}