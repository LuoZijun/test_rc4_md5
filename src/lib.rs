#![feature(test)]

extern crate rand;
extern crate openssl;
extern crate md5;
extern crate shadowsocks_crypto;
#[cfg(test)]
extern crate test;

use openssl::symm;
use md5::{Md5, Digest};
#[cfg(test)]
use shadowsocks_crypto::v1::{Cipher, CipherKind};


#[allow(dead_code)]
pub struct Rc4 {
    kind: symm::Cipher,
    cipher: symm::Crypter,
}

impl Rc4 {
    pub fn new(key: &[u8], iv: &[u8], mode: symm::Mode) -> Self {
        let kind = symm::Cipher::rc4();
        let cipher = symm::Crypter::new(kind, mode, key, Some(iv)).unwrap();

        Self { kind, cipher }
    }

    pub fn in_place(&mut self, in_out: &mut [u8]) {
        let input = unsafe {
            let ptr = in_out.as_ptr();
            let len = in_out.len();
            std::slice::from_raw_parts(ptr, len)
        };
        
        let out_len = self.cipher.update(input, in_out).unwrap();
        assert_eq!(in_out.len(), out_len);
    }
}


/// Rc4Md5 Cipher
pub struct Rc4Md5Cipher {
    cipher: Rc4,
}

impl Rc4Md5Cipher {
    pub const KEY_LEN: usize = 16;
    pub const IV_LEN: usize  = 16;


    pub fn new(key: &[u8], iv: &[u8], mode: symm::Mode) -> Self {
        let mut md5_digest = Md5::new();
        md5_digest.update(key);
        md5_digest.update(iv);

        let key = md5_digest.finalize();

        let cipher = Rc4::new(&key, b"", mode);

        Self { cipher }
    }

    pub fn in_place(&mut self, in_out: &mut [u8]) {
        self.cipher.in_place(in_out)
    }
}


pub fn random_bytes(bytes: &mut [u8]) {
    let mut rng = rand::thread_rng();
    rand::Rng::fill(&mut rng, bytes)
}

#[test]
fn test_rc4_md5_enc() {
    let mut key = [0u8; Rc4Md5Cipher::KEY_LEN];
    let mut iv = [0u8; Rc4Md5Cipher::IV_LEN];

    random_bytes(&mut key);
    random_bytes(&mut iv);

    let mut openssl_cipher = Rc4Md5Cipher::new(&key, &iv, symm::Mode::Encrypt);
    let mut ss_cipher = Cipher::new(CipherKind::SS_RC4_MD5, &key, &iv);

    let mut p1 = [0u8; 64];
    random_bytes(&mut p1);
    let mut p2 = p1.clone();

    for _ in 0..300 {
        openssl_cipher.in_place(&mut p1);
        ss_cipher.encrypt_packet(&mut p2);
        assert_eq!(&p1, &p2);
    }
}

#[test]
fn test_rc4_md5_dec() {
    let mut key = [0u8; Rc4Md5Cipher::KEY_LEN];
    let mut iv = [0u8; Rc4Md5Cipher::IV_LEN];

    random_bytes(&mut key);
    random_bytes(&mut iv);

    let mut openssl_cipher = Rc4Md5Cipher::new(&key, &iv, symm::Mode::Decrypt);
    let mut ss_cipher = Cipher::new(CipherKind::SS_RC4_MD5, &key, &iv);

    let mut c1 = [0u8; 64];
    random_bytes(&mut c1);
    let mut c2 = c1.clone();

    for _ in 0..300 {
        openssl_cipher.in_place(&mut c1);
        let _ = ss_cipher.decrypt_packet(&mut c2);
        assert_eq!(&c1, &c2);
    }
}
