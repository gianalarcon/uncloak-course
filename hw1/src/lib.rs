use rand::{rngs::ThreadRng, CryptoRng, Rng, RngCore};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

pub mod vignere {
  use std::iter::zip;

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
    pub fn encrypt(&self, plaintext: &str) -> anyhow::Result<Vec<u8>> {
      let key_it = self.key.iter().cycle();
      check_alphabetic(plaintext)?;
      let output: Vec<_> = zip(key_it, plaintext.as_bytes())
        .map(|(k, p)| {
          let k = k - b'a';
          let p = p - b'a';
          let c = (k + p) % 26;
          c + b'a'
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
      let test_ciphertext = "lxfopvefrnhr".as_bytes().to_vec();
      assert_eq!(ciphertext, test_ciphertext);
    }
  }
}
