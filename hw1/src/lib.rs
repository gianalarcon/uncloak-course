use rand::{rngs::ThreadRng, CryptoRng, Rng, RngCore};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

pub mod vignere {
  use std::{iter::zip, str::from_utf8};

  use anyhow::Ok;

  #[derive(Clone, Debug)]
  pub struct Vignere<'a> {
    key: &'a [u8],
  }

  fn check_alphabetic(s: &str) -> anyhow::Result<()> {
    for c in s.chars() {
      match c {
        'a'..='z' => (),
        _ => {
          return Err(anyhow::anyhow!(
            "Invalid character in key, must be lower case a-z: {c}"
          ))
        }
      }
    }
    Ok(())
  }

  impl<'a> Vignere<'a> {
    pub fn new(key: &'a str) -> anyhow::Result<Self> {
      check_alphabetic(key)?;
      Ok(Self {
        key: key.as_bytes(),
      })
    }
    pub fn encrypt(&self, plaintext: &str) -> anyhow::Result<String> {
      let key_it = self.key.iter().cycle();
      check_alphabetic(plaintext)?;
      let output = zip(key_it, plaintext.as_bytes())
        .map(|(k, p)| {
          let k = k - b'a';
          let p = p - b'a';
          let mut c = (k + p) % 26;
          c = c + b'a';
          c as char
        })
        .collect();
      Ok(output)
    }
    pub fn decrypt(&self, cyphertext: &str) -> anyhow::Result<String> {
      let key_it = self.key.iter().cycle();
      check_alphabetic(cyphertext)?;
      let output = zip(key_it, cyphertext.as_bytes())
        .map(|(k, c)| {
          let k = k - b'a';
          let c = c - b'a';
          let mut p = (c + 26 - k) % 26;
          p = p + b'a';
          p as char
        })
        .collect();
      Ok(output)
    }
  }

  #[cfg(test)]
  mod test {
    use super::*;
    #[test]
    fn test_vig() {
      let msg = "attackatdawn";
      let key = "lemon";
      let v = Vignere::new(key).unwrap();
      let ciphertext = v.encrypt(msg).unwrap();
      let ciphertext = ciphertext.as_str();
      let plaintext = v.decrypt(ciphertext).unwrap();
      assert_eq!(msg, plaintext);
    }
  }
}
