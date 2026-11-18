//! Opening the data partition. A phone encrypts the whole of it with a key
//! its storage hardware holds, and encrypts each user's files again with a
//! key only that user's credential leads to. This is the first of the two:
//! what it opens holds every file, with the names and contents of the ones
//! that are a user's own still encrypted.

use crate::encryption::{key_dir, target, Encryption, DEFAULT_KEY_DIR};
use crate::gatekeeper::Gatekeeper;
use crate::keymint::KeyMint;
use crate::keystore::{StoredKey, Unwrap};
use crate::token::Token;
use crate::user::Bound;
use crate::weaver::Weaver;
use anyhow::{Context, Result};
use skyward_binder::driver::Binder;
use skyward_block::fsck::Checked;
use skyward_block::fstab::Entry;
use skyward_block::{dm, mount};
use std::path::{Path, PathBuf};

/// Where the data partition is mounted, and the name its decrypted form is
/// given among the device-mapper's devices.
pub const MOUNT: &str = "/data";
pub const MAPPED: &str = "userdata";

/// Where the phone keeps the files its users share between apps, a folder
/// for each user, and where the recovery shows the owner's, the way the
/// phone shows them to apps.
pub const SHARED_STORAGE: &str = "/data/media";
pub const SDCARD: &str = "/sdcard";

/// The phone's owner, the first of its users.
const OWNER: u32 = 0;

/// Unwrap the key the phone keeps for its data partition and give the
/// storage hardware the form of it that lasts until the phone is started
/// again.
pub fn storage_key(service: &KeyMint, entry: &Entry, encryption: &Encryption) -> Result<Vec<u8>> {
    hardware_key(service, &key_dir(entry)?, encryption.wrapped)
}

/// Unwrap the metadata key at Android's fixed fallback path, for a table
/// that no longer says where or how it is kept.
fn default_storage_key(service: &KeyMint, encryption: &Encryption) -> Result<Vec<u8>> {
    hardware_key(service, Path::new(DEFAULT_KEY_DIR), encryption.wrapped)
}

/// The key a directory holds, in the form the storage hardware takes for
/// this start of the phone. A key the hardware holds never appears as
/// itself: what comes back is wrapped again, for this start only.
fn hardware_key(service: &KeyMint, dir: &Path, wrapped: bool) -> Result<Vec<u8>> {
    let stored = StoredKey::load(dir).with_context(|| format!("read the key in {}", dir.display()))?;
    let key = stored.unwrap(Unwrap::Hardware(service)).with_context(|| format!("unwrap the key in {}", dir.display()))?;
    match wrapped {
        true => service.ephemeral_storage_key(&key).with_context(|| format!("make the key in {} usable now", dir.display())),
        false => Ok(key),
    }
}

/// The data partition as [`open`] leaves it.
pub struct Opened {
    /// The device the partition is read and written through, decrypted.
    pub mapped: PathBuf,
    pub filesystem: String,
    /// How the check before mounting ended, where the phone's table asks
    /// for one.
    pub checked: Option<Checked>,
}

/// Open the phone's data partition: unwrap the key it is encrypted with,
/// give that to the storage hardware, check the filesystem where the
/// phone's table asks for it, and mount it writable, as the phone mounts
/// it. The names and contents of each user's own files stay encrypted
/// until that user's key is let in as well. A partition that does not
/// mount leaves no device behind.
fn open(service: &KeyMint) -> Result<Opened> {
    let (entries, mapped, wrapped) = map(service)?;
    let mounted = (|| -> Result<(Option<Checked>, String)> {
        // A phone that names the partition once per filesystem it might hold
        // mounts it with the entry of the one it holds. That is the entry
        // blkid names, and it is tried first; the table's other lines for
        // this mount point follow it, since one that names the wrong
        // filesystem first still names the right one somewhere.
        let holds = skyward_block::probe::filesystem(&mapped)?;
        let (matching, rest): (Vec<&Entry>, Vec<&Entry>) = entries.iter().partition(|e| holds.as_ref() == Some(&e.filesystem));
        std::fs::create_dir_all(MOUNT).with_context(|| format!("make {MOUNT}"))?;
        let mut scanned = false;
        let mut refused: Vec<String> = Vec::new();
        for entry in matching.into_iter().chain(rest) {
            let checked = match !scanned && holds.as_ref() == Some(&entry.filesystem) && entry.extras.iter().any(|e| e == "check") {
                true => {
                    scanned = true;
                    Some(skyward_block::fsck::check(&mapped, &entry.filesystem)?)
                }
                false => None,
            };
            match mount_data(&mapped, entry) {
                Ok(()) => return Ok((checked, entry.filesystem.clone())),
                Err(e) => refused.push(format!("{e:#}")),
            }
        }
        anyhow::bail!("{} holds no filesystem the phone's own table mounts ({})", mapped.display(), refused.join("; "))
    })();
    match mounted {
        Ok((checked, filesystem)) => Ok(Opened { mapped, filesystem, checked }),
        // A partition read where it lies was never mapped: there is no device
        // to take away, and asking for one only wraps the reason the mount
        // failed in an error about a device that was never made.
        Err(e) => match wrapped {
            false => Err(e),
            true => match dm::remove(MAPPED) {
                Ok(()) => Err(e),
                Err(r) => Err(e.context(format!("removing {MAPPED} afterwards failed too: {r:#}"))),
            },
        },
    }
}

/// Mount the data partition at /data as `entry` says, and where the kernel
/// will not take the options it names, again with none.
///
/// A phone's table is written for its own kernel, which need not be the one
/// the recovery runs: an option this kernel does not know fails the whole
/// mount with an argument error, and nothing in that error says which option
/// it was. The options tune the filesystem rather than make it readable, so
/// the mount is tried again without them.
fn mount_data(device: &Path, entry: &Entry) -> Result<()> {
    let at = Path::new(MOUNT);
    match mount::mount(device, at, &entry.filesystem, &entry.options) {
        Ok(()) => Ok(()),
        Err(e) if took_no_options(&e) => mount::mount(device, at, &entry.filesystem, &[])
            .with_context(|| format!("and again as {} without the options the kernel refused: {e:#}", entry.filesystem)),
        Err(e) => Err(e),
    }
}

/// Whether the kernel answered that it would not take what it was given: an
/// option it does not know, and a superblock it will not read, come back the
/// same way.
fn took_no_options(e: &anyhow::Error) -> bool {
    e.root_cause().downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::InvalidInput)
}

/// Map the data partition decrypted, under the key the phone keeps for it,
/// and give its table's entries, the device the filesystem is read and
/// written through, and whether that device is one this mapped.
///
/// A phone may keep the partition itself as it lies and encrypt only what
/// each user's own files hold. Then the table names no key, and there is
/// neither a key to unwrap nor a device to map: the partition is read
/// where it is.
fn map(service: &KeyMint) -> Result<(Vec<Entry>, PathBuf, bool)> {
    let entries = skyward_block::fstab::read(MOUNT)?;
    let first = entries.first().with_context(|| format!("the phone's own table says nothing about {MOUNT}"))?;
    // A phone may name the same mount point more than once, once per
    // filesystem it might hold, and only the line of the one it holds says
    // how that one is wrapped. An entry that names the encryption is taken
    // where the table has one, whichever of its lines that is.
    let entry = entries.iter().find(|e| e.extra("metadata_encryption").is_some()).unwrap_or(first);
    let device = skyward_block::fstab::device(entry)?;
    let sectors = skyward_block::size_bytes(&device)? / 512;
    if entry.extra("metadata_encryption").is_none() {
        // A phone may keep the partition itself as it lies and encrypt only
        // what each user's own files hold: where blkid sees that filesystem,
        // read it where it lies. Some builds lose the metadata-encryption
        // words from their table although vold still wrote the standard key;
        // where the raw partition holds no filesystem, try every form Android
        // has used and keep only one through which blkid finds a filesystem.
        if skyward_block::probe::filesystem(Path::new(&device))?.is_some() {
            return Ok((entries, PathBuf::from(device), false));
        }
        anyhow::ensure!(Path::new(DEFAULT_KEY_DIR).is_dir(), "{device} looks encrypted whole, the phone's own table says nothing of how, and {DEFAULT_KEY_DIR} is not there");
        let mut refused = Vec::new();
        for encryption in Encryption::defaults() {
            let about = format!("{} ({})", encryption.cipher, if encryption.wrapped { "hardware-wrapped" } else { "plain" });
            let key = match default_storage_key(service, &encryption) {
                Ok(key) => key,
                Err(e) => {
                    refused.push(format!("{about}: {e:#}"));
                    continue;
                }
            };
            let mapped = match dm::create(MAPPED, &[target(&device, sectors, &key, &encryption)], false) {
                Ok(mapped) => mapped,
                Err(e) => {
                    refused.push(format!("{about}: {e:#}"));
                    continue;
                }
            };
            let found = skyward_block::probe::filesystem(&mapped);
            match found {
                Ok(Some(_)) => return Ok((entries, mapped, true)),
                Ok(None) => refused.push(format!("{about}: the mapping holds no filesystem blkid names")),
                Err(e) => refused.push(format!("{about}: {e:#}")),
            }
            dm::remove(MAPPED).with_context(|| format!("remove the rejected {about} mapping"))?;
        }
        anyhow::bail!("{device} looks encrypted whole, the phone's own table says nothing of how, and none of Android's metadata-encryption forms opened it ({})", refused.join("; "));
    }
    let encryption = Encryption::of(entry)?;
    let key = storage_key(service, entry, &encryption)?;
    let mapped = dm::create(MAPPED, &[target(&device, sectors, &key, &encryption)], false)?;
    Ok((entries, mapped, true))
}

/// Map the data partition decrypted without mounting it, for its
/// filesystem to be repaired, and give the device it is reached through;
/// [`unmap`] takes it away again. The partition is to be closed.
pub fn map_unmounted(service: &KeyMint) -> Result<PathBuf> {
    anyhow::ensure!(dm::status(MAPPED)?.is_none(), "the data partition is open");
    map(service).map(|(_, mapped, _)| mapped)
}

/// Take away the mapping [`map_unmounted`] made, where one was made: a
/// partition read where it lies has no device to take away.
pub fn unmap() -> Result<()> {
    match dm::status(MAPPED)? {
        Some(_) => dm::remove(MAPPED),
        None => Ok(()),
    }
}

/// Show the owner's shared storage at /sdcard; shown already, it stays.
fn show_owner_storage() -> Result<()> {
    let at = Path::new(SDCARD);
    if mount::is_mount_point(at)? {
        return Ok(());
    }
    mount::bind(&Path::new(SHARED_STORAGE).join(OWNER.to_string()), at)
}

/// Close what opening the partition opened, where the recovery opened it:
/// /sdcard, the partition's mount, and the device it is read through.
pub fn close() -> Result<()> {
    for at in [SDCARD, MOUNT] {
        if mount::is_mount_point(Path::new(at))? {
            mount::umount(Path::new(at))?;
        }
    }
    if dm::status(MAPPED)?.is_some() {
        dm::remove(MAPPED)?;
    }
    Ok(())
}

/// A user whose own files are still closed: who, the kind of screen lock
/// they set in the phone's numbering, and whether the phone made their
/// credential up, in which case they open behind the owner and nobody is
/// asked for it. `why` says why such a user did not open behind the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closed {
    pub user: u32,
    pub lock: i32,
    pub made_up: bool,
    pub why: Option<String>,
}

/// The data partition as far as it opens with nothing a user knows.
pub struct Opening {
    /// How it was mounted, where this mounted it rather than an earlier
    /// run of the recovery.
    pub mounted: Option<Opened>,
    /// The users whose own files are still closed, the owner first.
    pub closed: Vec<Closed>,
}

/// Open the data partition as far as it opens with nothing a user knows:
/// mount it where it is not mounted, let in the keys of the files that
/// belong to no one user and of each user's files readable before they
/// sign in, and open the own files of every user who set no screen lock
/// and, behind the owner's, of those whose credential the phone made up.
pub fn open_without_credential(service: &KeyMint) -> Result<Opening> {
    let mounted = match mount::is_mount_point(Path::new(MOUNT))? {
        true => None,
        false => Some(open(service)?),
    };
    // A phone may keep nothing on the partition encrypted at all: then
    // there is no key to let in and no user whose own files stay closed,
    // and everything it holds reads as it was written. Asking the key
    // service for a key it has never been asked to make would only fail.
    if !kept_encrypted() {
        show_owner_storage()?;
        return Ok(Opening { mounted, closed: Vec::new() });
    }
    open_shared(service)?;
    let mut closed = Vec::new();
    let mut owner = Note::default();
    for user in open_users(service)? {
        let protector = protector(user)?;
        match protector.lock {
            None => {
                let note = open_user_files(service, user, None, None)?;
                if user == OWNER {
                    owner = note;
                }
            }
            Some(lock) => closed.push(Closed { user, lock: lock.kind, made_up: made_up(user, &protector.id), why: None }),
        }
    }
    Ok(Opening { mounted, closed: open_made_up(service, closed, &owner) })
}

/// Whether the phone keeps anything on its data partition encrypted. It
/// writes the key for the files readable before anyone signs in and a key
/// for each user, the latter under a directory named for the kind of key;
/// a phone that writes neither keeps nothing so, and its partition reads
/// as it lies. Android makes the folders either would go in regardless,
/// so what is looked for is the key itself, not the folder holding it.
fn kept_encrypted() -> bool {
    Path::new(SHARED_KEY).join("version").exists() || Path::new(USER_KEYS).join("de").exists()
}

/// Open the own files of `user` with what they typed at their screen lock
/// and, where `user` is the owner, of each of `closed` whose credential
/// the phone made up behind theirs; give those still closed.
pub fn unlock(service: &KeyMint, closed: &[Closed], user: u32, credential: &[u8]) -> Result<Vec<Closed>> {
    let note = open_user_files(service, user, Some(credential), None)?;
    let rest = closed.iter().filter(|c| c.user != user).cloned().collect();
    Ok(match user == OWNER {
        true => open_made_up(service, rest, &note),
        false => rest,
    })
}

/// Open the own files of each of `closed` whose credential the phone made
/// up, behind `owner`, the note the owner's own secret gave; give those
/// still closed, a made-up one with why it did not open. Where the secure
/// world wrote no note, none of them is tried and each is left with why.
fn open_made_up(service: &KeyMint, closed: Vec<Closed>, owner: &Note) -> Vec<Closed> {
    let Some(token) = &owner.token else {
        return closed
            .into_iter()
            .map(|c| match c.made_up {
                true => Closed { why: owner.refused.clone(), ..c },
                false => c,
            })
            .collect();
    };
    closed
        .into_iter()
        .filter_map(|c| match c.made_up {
            false => Some(c),
            true => match open_user_files(service, c.user, None, Some(token)) {
                Ok(_) => None,
                Err(e) => Some(Closed { why: Some(format!("{e:#}")), ..c }),
            },
        })
        .collect()
}

/// Whether the phone made up the credential of `user`, whose protector is
/// `id`, keeping it behind the owner's.
fn made_up(user: u32, id: &str) -> bool {
    made_up_record(user, id).is_some()
}

/// Where the phone keeps the key for the files that are readable before
/// anyone signs in, and what it says about how those files are encrypted.
const SHARED_KEY: &str = "/data/unencrypted/key";
const SHARED_NAME: &str = "/data/unencrypted/ref";
const FILE_MODE: &str = "/data/unencrypted/mode";

/// Where the phone keeps each user's own keys.
const USER_KEYS: &str = "/data/misc/vold/user_keys";

/// Let in the key for the files that belong to no one user. Until it is
/// in, most of what the data partition holds reads as scrambled names.
fn open_shared(service: &KeyMint) -> Result<[u8; crate::fscrypt::NAME_BYTES]> {
    let mode = std::fs::read_to_string(FILE_MODE).with_context(|| format!("read {FILE_MODE}"))?;
    let wrapped = crate::fscrypt::hardware_wrapped(mode.trim());
    let raw = hardware_key(service, Path::new(SHARED_KEY), wrapped)?;
    let name = crate::fscrypt::add_key(Path::new(MOUNT), &raw, wrapped)?;
    let recorded = crate::fscrypt::recorded_name(Path::new(SHARED_NAME))?;
    if name != recorded {
        anyhow::bail!("the key in {SHARED_KEY} is not the one {SHARED_NAME} names");
    }
    Ok(name)
}

/// Which users the phone keeps keys for, in order.
fn users() -> Result<Vec<u32>> {
    let dir = Path::new(USER_KEYS).join("de");
    let mut users = Vec::new();
    for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry.with_context(|| format!("read {}", dir.display()))?.path();
        let Some(user) = path.file_name().and_then(|n| n.to_str()).and_then(|n| n.parse::<u32>().ok()) else { continue };
        users.push(user);
    }
    users.sort_unstable();
    Ok(users)
}

/// Let in the keys for the files of each user that are readable before
/// that user signs in, and give the users they belong to.
fn open_users(service: &KeyMint) -> Result<Vec<u32>> {
    let mode = std::fs::read_to_string(FILE_MODE).with_context(|| format!("read {FILE_MODE}"))?;
    let wrapped = crate::fscrypt::hardware_wrapped(mode.trim());
    let users = users()?;
    for user in &users {
        let dir = Path::new(USER_KEYS).join("de").join(user.to_string());
        let raw = hardware_key(service, &dir, wrapped)?;
        crate::fscrypt::add_key(Path::new(MOUNT), &raw, wrapped)?;
    }
    Ok(users)
}

/// Where a phone keeps what it needs to recover a user's own secret.
const PROTECTORS: &str = "/data/system_de";

/// Read what a user's own credential keeps their secret behind. A phone
/// may keep more than one blob for a user: Android keeps one for each
/// token some part of the phone was given to reach the secret with, and
/// HyperOS, once the owner changes one screen lock for another with a
/// fingerprint enrolled, keeps a second one for a while, so that the
/// credential before can still be used. Which of them the user's current
/// credential opens is the phone's own business, and it writes that down,
/// so this reads it rather than guess.
fn protector(user: u32) -> Result<crate::user::Protector> {
    let dir = blobs(user);
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry.with_context(|| format!("read {}", dir.display()))?.path();
        if path.extension().is_some_and(|e| e == "spblob")
            && let Some(id) = path.file_stem().and_then(|s| s.to_str())
        {
            ids.push(id.to_string());
        }
    }
    let id = match crate::locksettings::current_protector(Path::new(crate::locksettings::DATABASE), user)? {
        Some(recorded) => {
            anyhow::ensure!(
                ids.contains(&recorded),
                "the phone keeps user {user}'s secret behind the blob {recorded}, which is not among the {} in {}",
                ids.len(),
                dir.display()
            );
            recorded
        }
        // Where the phone records none, only a blob that is alone is
        // beyond doubt the user's.
        None => match &ids[..] {
            [only] => only.clone(),
            _ => anyhow::bail!(
                "{} holds {} of the user's blobs, and the phone records none of them as the one the user's own credential opens",
                dir.display(),
                ids.len()
            ),
        },
    };
    // A user who has set a screen lock has what the phone recorded about
    // it beside the blob; a user who has set none has nothing there.
    let recorded = dir.join(format!("{id}.pwd"));
    let lock = match recorded.exists() {
        true => Some(crate::user::Lock::of(
            &std::fs::read(&recorded).with_context(|| format!("read {}", recorded.display()))?,
        )?),
        false => None,
    };
    // A phone with a weaver records the slot it keeps for the blob; any
    // other keeps the bytes the blob is bound to beside it.
    let slot = dir.join(format!("{id}.weaver"));
    let bound = match slot.exists() {
        true => Bound::Weaver(crate::user::weaver_slot(&std::fs::read(&slot).with_context(|| format!("read {}", slot.display()))?)?),
        false => Bound::Secdiscardable(
            std::fs::read(dir.join(format!("{id}.secdis"))).with_context(|| format!("read what the blob in {} is bound to", dir.display()))?,
        ),
    };
    Ok(crate::user::Protector {
        blob: std::fs::read(dir.join(format!("{id}.spblob"))).with_context(|| format!("read the blob in {}", dir.display()))?,
        bound,
        id,
        lock,
    })
}

/// Which of the secure world's slots a user's enrolments sit in. What the
/// user types is enrolled a hundred thousand above their own number,
/// keeping it apart from the enrolments made before phones kept
/// credentials this way; the secret behind it is enrolled under the
/// number itself.
const TYPED_SLOT: u32 = 100_000;

/// What the phone calls the enrolment of a user's own secret, among the
/// blobs it keeps for that user.
const BLOBS: &str = "spblob";
const SECRET_HANDLE: &str = "0000000000000000.handle";

/// Where a user's blobs are.
fn blobs(user: u32) -> PathBuf {
    Path::new(PROTECTORS).join(user.to_string()).join(BLOBS)
}

/// Where a phone keeps the credential it made up itself for a user whose
/// screen lock is the owner's. The file holds a nonce and then the
/// credential, encrypted under a key the owner's own secret guards.
const MADE_UP: &str = "/data/system/users";
const MADE_UP_FILE: &str = "gatekeeper.profile.key";

/// The name the key service keeps that key under, the user's number after
/// it.
const MADE_UP_KEY: &str = "profile_key_name_decrypt_";

/// HyperOS keeps the file beside the blob of the user's protector instead,
/// named after the protector with this ending, and puts the protector's
/// name after the user's number in the key's name too.
const MADE_UP_BESIDE_BLOB: &str = "profile_pwd";

/// The file holding the credential the phone made up for `user`, whose
/// protector is `id`, and the name of the key it is encrypted under: where
/// Android keeps them, or where HyperOS does. `None` where it made none up.
fn made_up_record(user: u32, id: &str) -> Option<(PathBuf, String)> {
    let android = Path::new(MADE_UP).join(user.to_string()).join(MADE_UP_FILE);
    if android.is_file() {
        return Some((android, format!("{MADE_UP_KEY}{user}")));
    }
    let hyperos = blobs(user).join(format!("{id}.{MADE_UP_BESIDE_BLOB}"));
    hyperos.is_file().then(|| (hyperos, format!("{MADE_UP_KEY}{user}.{id}")))
}

/// The credential a phone made up for `user`, whose protector is `id`,
/// where it made one up. A phone does this for the users it keeps beside
/// the owner's own, such as the one that holds a second copy of an app:
/// nobody ever types their credential, so the phone writes one down for
/// itself and keeps it behind the owner's. `owner` is the note the owner's
/// credential gave.
fn made_up_credential(service: &KeyMint, user: u32, id: &str, owner: Option<&Token>) -> Result<Option<Vec<u8>>> {
    let Some((file, alias)) = made_up_record(user, id) else { return Ok(None) };
    let stored = std::fs::read(&file).with_context(|| format!("read {}", file.display()))?;
    if stored.len() < NONCE_BYTES + TAG_BYTES {
        anyhow::bail!("{} is {} bytes, too few to hold a credential", file.display(), stored.len());
    }
    let (nonce, body) = stored.split_at(NONCE_BYTES);
    let held = crate::keystore2::key_blob(Path::new(crate::keystore2::DATABASE), &alias)?;
    let credential = service.gcm_decrypt(&held, &[], nonce, body, owner).with_context(|| {
        format!("open the credential the phone made up for user {user}, which is kept behind the owner's own")
    })?;
    Ok(Some(credential))
}

/// How long the nonce and the check are on everything the key service
/// encrypts.
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

/// Let in the key for a user's own files, and give the note the secure
/// world wrote for the secret behind their credential, which is what the
/// keys the phone keeps for them are guarded by. `credential` is what the
/// user would type at their screen lock; a user who has set none needs
/// none, and a user the phone made one up for needs `owner`, the note the
/// owner's own secret gave. The owner's files open, their shared storage
/// shows at /sdcard.
fn open_user_files(service: &KeyMint, user: u32, credential: Option<&[u8]>, owner: Option<&Token>) -> Result<Note> {
    let protector = protector(user)?;
    let stretched = match &protector.lock {
        Some(lock) => {
            let typed = match made_up_credential(service, user, &protector.id, owner)? {
                Some(made_up) => made_up,
                None => credential
                    .with_context(|| format!("user {user} has set a screen lock, and their files do not open without it"))?
                    .to_vec(),
            };
            lock.stretched(&typed).context("stretch the credential")?
        }
        None => crate::user::stretched_without_credential(),
    };
    let (secret, note) = match (&protector.bound, &protector.lock) {
        // The weaver checks the credential itself, and gives back the value
        // the secret is bound to only for the right one. The key holding
        // the secret is then guarded by nothing else.
        (Bound::Weaver(slot), _) => {
            let binder = Binder::open()?;
            let weaver = Weaver::open(&binder)?;
            let key = crate::user::weaver_key(&stretched, weaver.config()?.key_bytes)?;
            let value = weaver.read(*slot, &key)?;
            (crate::user::weaver_protector_secret(&stretched, &value), None)
        }
        // The key holding this user's secret is guarded by the screen lock,
        // so the secure world has to be shown the credential itself before
        // it will use that key.
        (Bound::Secdiscardable(secdiscardable), Some(lock)) => {
            let (binder, hardware) = (Binder::open()?, Binder::hardware()?);
            let note = Gatekeeper::open(&binder, &hardware)?.verify(
                TYPED_SLOT + user,
                &lock.enrolled,
                &crate::user::gatekeeper_password(&stretched),
            )?;
            (crate::user::protector_secret(&stretched, secdiscardable), Some(note))
        }
        (Bound::Secdiscardable(secdiscardable), None) => (crate::user::protector_secret(&stretched, secdiscardable), None),
    };
    let held = crate::keystore2::key_blob(Path::new(crate::keystore2::DATABASE), &protector.key_alias())?;
    let content = crate::user::content(&protector.blob)?;
    if content.len() < NONCE_BYTES + TAG_BYTES {
        anyhow::bail!("the user's blob is too short to hold anything");
    }
    let (nonce, body) = content.split_at(NONCE_BYTES);
    let inner = service
        .gcm_decrypt(&held, &[], nonce, body, note.as_ref())
        .context("open what the secure world holds the user's blob closed with")?;
    let synthetic_password = crate::user::open_inner(&secret, &inner)?;
    let file_secret = crate::user::file_secret(&synthetic_password);

    let mode = std::fs::read_to_string(FILE_MODE).with_context(|| format!("read {FILE_MODE}"))?;
    let wrapped = crate::fscrypt::hardware_wrapped(mode.trim());
    let dir = Path::new(USER_KEYS).join("ce").join(user.to_string()).join("current");
    let stored = StoredKey::load(&dir).with_context(|| format!("read the key in {}", dir.display()))?;
    let raw = stored.unwrap(Unwrap::<KeyMint>::Secret(&file_secret)).with_context(|| format!("unwrap the key in {}", dir.display()))?;
    let raw = match wrapped {
        true => service.ephemeral_storage_key(&raw).with_context(|| format!("make the key in {} usable now", dir.display()))?,
        false => raw,
    };
    crate::fscrypt::add_key(Path::new(MOUNT), &raw, wrapped)?;
    if user == OWNER {
        show_owner_storage()?;
    }
    secret_note(user, &synthetic_password)
}

/// What the secure world wrote for a user's own secret, which is what the
/// credentials the phone made up for other users are kept behind. A user
/// whose secret the secure world knows nothing about has none, and so has
/// one whose secure world would write none; the user's own files are open
/// either way, and only the users kept behind this one stay closed.
#[derive(Debug, Default)]
struct Note {
    token: Option<Token>,
    /// Why the secure world wrote none, where it was asked and would not.
    refused: Option<String>,
}

/// Have the secure world check the user's own secret, so the keys the
/// phone keeps for that user can be used.
fn secret_note(user: u32, synthetic_password: &[u8]) -> Result<Note> {
    let handle = blobs(user).join(SECRET_HANDLE);
    if !handle.is_file() {
        return Ok(Note::default());
    }
    let enrolled = std::fs::read(&handle).with_context(|| format!("read {}", handle.display()))?;
    let (binder, hardware) = (Binder::open()?, Binder::hardware()?);
    let password = crate::user::secret_gatekeeper_password(synthetic_password);
    let asked = Gatekeeper::open(&binder, &hardware)
        .and_then(|gatekeeper| gatekeeper.verify(user, &enrolled, &password))
        .with_context(|| format!("have the secure world check the secret behind user {user}'s credential"));
    Ok(match asked {
        Ok(token) => Note { token: Some(token), refused: None },
        Err(e) => Note { token: None, refused: Some(format!("{e:#}")) },
    })
}
