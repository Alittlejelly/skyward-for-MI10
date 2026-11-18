use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha512};
use std::fs;
use std::path::Path;

/// A hash is personalised by a fixed prefix padded out to one SHA-512 block,
/// so the same bytes hashed for two purposes never agree.
const PREFIX_BYTES: usize = 128;

const SECDISCARDABLE_PREFIX: &[u8] = b"Android secdiscardable SHA512";
const KEYGEN_PREFIX: &[u8] = b"Android key wrapping key generation SHA512";

const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const KEY_BYTES: usize = 32;

/// The only layout Android writes these directories in.
const VERSION: &str = "1";

const FN_VERSION: &str = "version";
const FN_ENCRYPTED_KEY: &str = "encrypted_key";
const FN_KEY_BLOB: &str = "keymaster_key_blob";
const FN_SECDISCARDABLE: &str = "secdiscardable";
const FN_STRETCHING: &str = "stretching";
const FN_SALT: &str = "salt";

/// What a stretched secret comes to, as Android writes it. It is a block of
/// its own, and not the length the screen lock's credential is stretched to.
const STRETCHED_BYTES: usize = 64;

/// The words Android writes of how it stretched the secret the key is
/// wrapped by, and the one it puts before the costs of scrypt.
const STRETCH_NOPASSWORD: &str = "nopassword";
const STRETCH_NONE: &str = "none";
const STRETCH_PREFIX: &str = "scrypt ";

/// SHA-512 of `data` behind a fixed prefix.
pub fn hash_with_prefix(prefix: &[u8], data: &[u8]) -> Vec<u8> {
    let mut padded = prefix.to_vec();
    padded.resize(PREFIX_BYTES, 0);
    let mut h = Sha512::new();
    h.update(&padded);
    h.update(data);
    h.finalize().to_vec()
}

/// Where a wrapped key's wrapping comes from.
pub enum Unwrap<'a, K: Decryptor> {
    /// The phone's key service holds the wrapping key in hardware. Nothing
    /// the user knows is needed, so this is how the metadata key and the
    /// keys for data that is readable before anyone signs in are kept.
    Hardware(&'a K),
    /// A secret only the user's credential leads to wraps the key, in
    /// software. This is how each user's own data is kept.
    Secret(&'a [u8]),
}

/// What can undo an AES-GCM encryption bound to an application id. The key
/// service on the phone is the one that can; naming it this way keeps the
/// key handling testable away from a phone.
pub trait Decryptor {
    fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> Result<Vec<u8>>;
}

/// How the secret a key is wrapped by becomes the application id the
/// wrapping is bound to, as the phone wrote it beside the key.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Stretching {
    /// Nothing of a secret enters it: the key is wrapped by the hardware
    /// alone, which is what a phone that can use its key service writes.
    Hardware,
    /// The secret enters as itself.
    AsIs,
    /// The secret is stretched with scrypt, at the costs and with the salt
    /// the phone wrote beside it.
    Scrypt { cost: [u8; 3], salt: Vec<u8> },
}

impl Stretching {
    /// Read what the phone wrote, and the salt it wrote beside it where the
    /// stretching takes one. A directory written before the phone recorded
    /// this at all says nothing, and the secret then enters as it is.
    fn of(said: Option<&str>, salt: Option<Vec<u8>>) -> Result<Stretching> {
        let Some(said) = said else { return Ok(Stretching::AsIs) };
        let said = said.trim();
        match said {
            STRETCH_NOPASSWORD => Ok(Stretching::Hardware),
            STRETCH_NONE => Ok(Stretching::AsIs),
            _ => {
                let costs = said
                    .strip_prefix(STRETCH_PREFIX)
                    .with_context(|| format!("the phone stretches the secret with {said}, which this recovery does not know"))?;
                let numbers: Vec<&str> = costs.split_whitespace().collect();
                let [log_n, log_r, log_p] = numbers[..] else {
                    bail!("the phone's stretching of {said} does not name three costs");
                };
                let read = |n: &str| n.parse::<u8>().with_context(|| format!("read the cost {n} of {said}"));
                let cost = [read(log_n)?, read(log_r)?, read(log_p)?];
                let salt = salt.with_context(|| format!("the phone stretches the secret with {said}, and wrote no {FN_SALT} beside it"))?;
                Ok(Stretching::Scrypt { cost, salt })
            }
        }
    }

    /// What the secret becomes before it is joined to the directory's hash.
    fn stretched(&self, secret: &[u8]) -> Result<Vec<u8>> {
        match self {
            Stretching::Hardware => Ok(Vec::new()),
            Stretching::AsIs => Ok(secret.to_vec()),
            Stretching::Scrypt { cost, salt } => {
                let [log_n, log_r, log_p] = *cost;
                let costs = scrypt::Params::new(log_n, 1 << log_r, 1 << log_p, STRETCHED_BYTES)
                    .map_err(|e| anyhow::anyhow!("the phone asks for stretching this code cannot do: {e}"))?;
                let mut out = vec![0u8; STRETCHED_BYTES];
                scrypt::scrypt(secret, salt, &costs, &mut out).map_err(|e| anyhow::anyhow!("stretch the secret: {e}"))?;
                Ok(out)
            }
        }
    }
}

/// One wrapped key as Android leaves it on disk.
pub struct StoredKey {
    encrypted: Vec<u8>,
    key_blob: Option<Vec<u8>>,
    /// The hash of the blob whose erasure makes the key unrecoverable.
    /// Directories written without one hash nothing.
    secdiscardable_hash: Vec<u8>,
    /// How the secret the key is wrapped by becomes the application id.
    stretching: Stretching,
}

impl StoredKey {
    pub fn load(dir: &Path) -> Result<StoredKey> {
        let read = |name: &str| fs::read(dir.join(name)).with_context(|| format!("read {}", dir.join(name).display()));
        let version = fs::read_to_string(dir.join(FN_VERSION)).with_context(|| format!("read {}", dir.join(FN_VERSION).display()))?;
        if version.trim() != VERSION {
            bail!("{} is written in layout {}, Skyward reads layout {VERSION}", dir.display(), version.trim());
        }
        let said = match dir.join(FN_STRETCHING).exists() {
            true => Some(fs::read_to_string(dir.join(FN_STRETCHING)).with_context(|| format!("read {}", dir.join(FN_STRETCHING).display()))?),
            false => None,
        };
        let salt = match dir.join(FN_SALT).exists() {
            true => Some(read(FN_SALT)?),
            false => None,
        };
        let stretching = Stretching::of(said.as_deref(), salt).with_context(|| format!("read how {} was written", dir.display()))?;
        let secdiscardable_hash = match dir.join(FN_SECDISCARDABLE).exists() {
            true => hash_with_prefix(SECDISCARDABLE_PREFIX, &read(FN_SECDISCARDABLE)?),
            false => Vec::new(),
        };
        let key_blob = match dir.join(FN_KEY_BLOB).exists() {
            true => Some(read(FN_KEY_BLOB)?),
            false => None,
        };
        Ok(StoredKey { encrypted: read(FN_ENCRYPTED_KEY)?, key_blob, secdiscardable_hash, stretching })
    }

    /// What the wrapping is bound to: the directory's own hash and whatever
    /// secret guards it, stretched as the phone wrote. A wrong secret gives a
    /// wrong binding, and the unwrapping fails rather than producing a key
    /// that looks usable.
    fn app_id(&self, secret: &[u8]) -> Result<Vec<u8>> {
        let mut id = self.secdiscardable_hash.clone();
        id.extend_from_slice(&self.stretching.stretched(secret)?);
        Ok(id)
    }

    /// What the phone's key service says the wrapping key may be used for.
    #[cfg(target_os = "android")]
    pub fn authorizations(&self, service: &crate::keymint::KeyMint) -> Result<Vec<(i32, i64)>> {
        let blob = self.key_blob.as_ref().context("this key is wrapped by a secret, not by the key service")?;
        service.authorizations(blob, &self.app_id(&[])?)
    }

    /// The wrapping the phone's key service holds, where it holds one.
    pub fn key_blob(&self) -> Option<&[u8]> {
        self.key_blob.as_deref()
    }

    /// The key itself.
    pub fn unwrap<K: Decryptor>(&self, how: Unwrap<K>) -> Result<Vec<u8>> {
        if self.encrypted.len() < NONCE_BYTES + TAG_BYTES {
            bail!("the wrapped key is {} bytes, too few to hold anything", self.encrypted.len());
        }
        let (nonce, body) = self.encrypted.split_at(NONCE_BYTES);
        match how {
            Unwrap::Hardware(service) => {
                let blob = self
                    .key_blob
                    .as_ref()
                    .context("this key is wrapped by a secret, and none was given")?;
                service.gcm_decrypt(blob, &self.app_id(&[])?, nonce, body)
            }
            Unwrap::Secret(secret) => decrypt_with_secret(&self.app_id(secret)?, nonce, body),
        }
    }
}

/// Undo the software wrapping, whose key is `pre_key` hashed for that
/// purpose.
fn decrypt_with_secret(pre_key: &[u8], nonce: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let mut key = hash_with_prefix(KEYGEN_PREFIX, pre_key);
    key.truncate(KEY_BYTES);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(nonce), body)
        .map_err(|_| anyhow::anyhow!("the wrapped key did not come apart; the secret is not the one it was wrapped with"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both hashes are checked against SHA-512 taken outside this code, so a
    /// change to the padding or the prefix shows up here.
    #[test]
    fn a_prefixed_hash_is_the_block_of_prefix_then_the_bytes() {
        let secdiscardable = hash_with_prefix(SECDISCARDABLE_PREFIX, b"test");
        assert_eq!(
            hex::encode(secdiscardable),
            "d29166a7b1dc78f68cdcb0e473a2d53421c932ee938167a2f41784e7f52adde2\
             02256f9eb3dcba42f08eef5be27bc87090e56c5b9099996f502939ab8961abcf"
        );
        let keygen = hash_with_prefix(KEYGEN_PREFIX, b"secret");
        assert_eq!(
            hex::encode(keygen),
            "1f0f944ae6b818481d8026af59a336cd84d6847475fa28196fc424a23794f21b\
             bae4f35a8be077f2c3fed1e4e5adbb58f1f97d522f5131b8cedcf4102478049d"
        );
    }

    /// Wrap a key the way Android does, to read it back.
    fn wrap(pre_key: &[u8], nonce: &[u8; NONCE_BYTES], key: &[u8]) -> Vec<u8> {
        let mut aes = hash_with_prefix(KEYGEN_PREFIX, pre_key);
        aes.truncate(KEY_BYTES);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes));
        let mut out = nonce.to_vec();
        out.extend_from_slice(&cipher.encrypt(Nonce::from_slice(nonce), key).expect("wrap"));
        out
    }

    struct NoService;

    impl Decryptor for NoService {
        fn gcm_decrypt(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
            bail!("no key service here")
        }
    }

    fn stored(secdiscardable: &[u8], encrypted: Vec<u8>) -> StoredKey {
        StoredKey {
            encrypted,
            key_blob: None,
            secdiscardable_hash: hash_with_prefix(SECDISCARDABLE_PREFIX, secdiscardable),
            stretching: Stretching::AsIs,
        }
    }

    #[test]
    fn a_key_wrapped_by_a_secret_comes_back_whole() {
        let key = [0xABu8; 64];
        let blob = [7u8; 256];
        let hash = hash_with_prefix(SECDISCARDABLE_PREFIX, &blob);
        let mut pre_key = hash.clone();
        pre_key.extend_from_slice(b"the user's secret");
        let s = stored(&blob, wrap(&pre_key, &[1; NONCE_BYTES], &key));
        assert_eq!(s.unwrap(Unwrap::<NoService>::Secret(b"the user's secret")).unwrap(), key.to_vec());
    }

    #[test]
    fn a_wrong_secret_is_refused_rather_than_giving_a_key() {
        let blob = [7u8; 256];
        let mut pre_key = hash_with_prefix(SECDISCARDABLE_PREFIX, &blob);
        pre_key.extend_from_slice(b"right");
        let s = stored(&blob, wrap(&pre_key, &[1; NONCE_BYTES], &[0xCDu8; 64]));
        let said = format!("{:#}", s.unwrap(Unwrap::<NoService>::Secret(b"wrong")).unwrap_err());
        assert!(said.contains("not the one it was wrapped with"), "{said}");
    }

    #[test]
    fn the_directory_it_came_from_is_bound_in() {
        let key = [0x11u8; 32];
        let mut pre_key = hash_with_prefix(SECDISCARDABLE_PREFIX, b"this directory");
        pre_key.extend_from_slice(b"s");
        let wrapped = wrap(&pre_key, &[2; NONCE_BYTES], &key);
        assert_eq!(stored(b"this directory", wrapped.clone()).unwrap(Unwrap::<NoService>::Secret(b"s")).unwrap(), key.to_vec());
        assert!(stored(b"another directory", wrapped).unwrap(Unwrap::<NoService>::Secret(b"s")).is_err());
    }

    #[test]
    fn a_key_the_hardware_holds_cannot_be_unwrapped_by_a_secret_alone() {
        let s = stored(b"x", vec![0; NONCE_BYTES + TAG_BYTES + 32]);
        let said = format!("{:#}", s.unwrap(Unwrap::Hardware(&NoService)).unwrap_err());
        assert!(said.contains("wrapped by a secret"), "{said}");
    }

    #[test]
    fn a_wrapped_key_too_short_to_hold_anything_is_refused() {
        let s = stored(b"x", vec![0; 20]);
        assert!(s.unwrap(Unwrap::<NoService>::Secret(b"s")).is_err());
    }

    #[test]
    fn the_stretching_the_phone_wrote_is_read_as_it_stands() {
        assert_eq!(Stretching::of(None, None).unwrap(), Stretching::AsIs, "a directory that says nothing keeps the secret as it is");
        assert_eq!(Stretching::of(Some("nopassword\n"), None).unwrap(), Stretching::Hardware);
        assert_eq!(Stretching::of(Some("none"), None).unwrap(), Stretching::AsIs);
        assert_eq!(
            Stretching::of(Some("scrypt 15 8 1"), Some(b"a salt".to_vec())).unwrap(),
            Stretching::Scrypt { cost: [15, 8, 1], salt: b"a salt".to_vec() }
        );
        assert!(Stretching::of(Some("scrypt 15 8 1"), None).is_err(), "a stretched secret needs the salt written beside it");
        assert!(Stretching::of(Some("scrypt 15 8"), Some(Vec::new())).is_err(), "three costs are what it writes");
        assert!(Stretching::of(Some("rot13"), None).is_err(), "a word this recovery does not know");
    }

    #[test]
    fn a_stretched_secret_is_a_block_of_the_cost_the_phone_wrote() {
        let stretching = Stretching::Scrypt { cost: [1, 1, 1], salt: b"0123456789abcdef".to_vec() };
        let one = stretching.stretched(b"secret").unwrap();
        assert_eq!(one.len(), STRETCHED_BYTES);
        assert_ne!(one, b"secret".to_vec(), "the secret does not enter as itself");
        assert_eq!(one, stretching.stretched(b"secret").unwrap(), "the same secret and salt agree");
        assert_ne!(one, stretching.stretched(b"another secret").unwrap());
        assert_eq!(Stretching::Hardware.stretched(b"secret").unwrap(), Vec::<u8>::new(), "nothing of a secret enters");
        assert_eq!(Stretching::AsIs.stretched(b"secret").unwrap(), b"secret".to_vec());
    }

    #[test]
    fn a_directory_in_another_layout_is_refused() {
        let dir = tempdir("other-layout");
        fs::write(dir.join(FN_VERSION), "1").unwrap();
        fs::write(dir.join(FN_ENCRYPTED_KEY), [0u8; 64]).unwrap();
        fs::write(dir.join(FN_STRETCHING), "scrypt 15 8 1").unwrap();
        assert!(refusal(&dir).contains(FN_SALT), "the salt the stretching takes: {}", refusal(&dir));
        fs::write(dir.join(FN_SALT), [9u8; 16]).unwrap();
        assert!(StoredKey::load(&dir).is_ok(), "the stretching is read once its salt is beside it");
        fs::write(dir.join(FN_VERSION), "2").unwrap();
        assert!(refusal(&dir).contains("layout 2"), "{}", refusal(&dir));
    }

    #[test]
    fn a_directory_without_a_secdiscardable_blob_binds_to_nothing_extra() {
        let dir = tempdir("no-secdiscardable");
        let key = [0x22u8; 32];
        fs::write(dir.join(FN_VERSION), "1").unwrap();
        fs::write(dir.join(FN_ENCRYPTED_KEY), wrap(b"only the secret", &[3; NONCE_BYTES], &key)).unwrap();
        let s = StoredKey::load(&dir).unwrap();
        assert!(s.secdiscardable_hash.is_empty());
        assert_eq!(s.unwrap(Unwrap::<NoService>::Secret(b"only the secret")).unwrap(), key.to_vec());
    }

    /// Why loading the directory was turned down.
    fn refusal(dir: &Path) -> String {
        match StoredKey::load(dir) {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("{} was read where it should have been refused", dir.display()),
        }
    }

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("skyward-keystore-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
