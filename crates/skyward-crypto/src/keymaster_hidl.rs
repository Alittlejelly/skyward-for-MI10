//! The phone's key service as this build of the hardware carries it: a
//! hardware service of the older kind, which registers with the second
//! directory and is reached over the second driver.
//!
//! Calls here differ from the newer kind in one way that matters: what is
//! longer than a word is not carried among the call's own words, but named
//! by a frame that says where the bytes lie and how many there are. This
//! file reads what the service answers and, for now, only what it answers
//! without being asked to change or reveal anything: what it says of
//! itself, and what it says a key may be used for. Those two replies carry
//! every kind of value the rest of the interface uses, so what is learnt
//! from them is what the rest is written against.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use anyhow::{bail, ensure, Context, Result};
use skyward_binder::hidl::{Answer, Message, Param};
use std::fmt;

/// The key service, as the phone's own description names it.
pub const SERVICE: &str = "android.hardware.keymaster@4.1::IKeymasterDevice";
pub const INSTANCE: &str = "default";

/// The name a call is opened with. Every version of an interface answers
/// its own methods only under the name that version declared them under,
/// and this one's first nineteen were declared by version 4.0: a call
/// opened with the newer name is turned away before its method is looked
/// at. Only what 4.1 adds is asked for under 4.1.
pub const CALLER: &str = "android.hardware.keymaster@4.0::IKeymasterDevice";

/// Where each method falls in the interface. The version 4 rewrite
/// declares its methods afresh rather than adding to the version 1 ones,
/// so the numbering starts again at one; the two methods 4.1 adds come
/// after these.
const GET_HARDWARE_INFO: u32 = 1;
const GET_KEY_CHARACTERISTICS: u32 = 9;
pub const UPGRADE_KEY: u32 = 12;
pub const BEGIN: u32 = 16;
pub const UPDATE: u32 = 17;
pub const FINISH: u32 = 18;
pub const ABORT: u32 = 19;

/// The two calls made here, named for a caller that sends one itself.
pub const SELF: u32 = GET_HARDWARE_INFO;
pub const USES: u32 = GET_KEY_CHARACTERISTICS;

/// A string the service answers is a frame saying how many characters
/// follow, and the characters behind it. Neither the terminator nor the
/// padding past it is counted.
const FRAME_BYTES: usize = 16;

/// What the key service says about its hardware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardware {
    /// How strongly the service says it is protected: 1 is a secure
    /// element, 2 the secure world of the processor.
    pub security_level: i32,
    pub name: String,
    pub author: String,
}

/// The versions of the phone's older key service, the newest first. Which
/// of them a phone carries follows the release of Android its vendor
/// partition was built for, and a table of the data partition written by one
/// of those releases names its key to the service of that release.
pub const VERSIONS: [&str; 3] = ["4.1", "4.0", "3.0"];

/// The name the older key service of `version` is registered under.
pub fn service(version: &str) -> String {
    format!("android.hardware.keymaster@{version}::IKeymasterDevice")
}

/// Which versions of the older key service the phone has registered. A
/// phone whose system hands its keys to the newer kind runs one of these
/// all the same, for the programs its vendor partition carries, so a phone
/// that answers with none here runs no key service at all.
///
/// The directory these register with is started only where a program is
/// asked for, so asking before anything has started it fails rather than
/// answering nothing; that is why this fails too instead of saying none.
#[cfg(target_os = "android")]
pub fn running(hardware: &skyward_binder::driver::Binder) -> Result<Vec<String>> {
    let mut found = Vec::new();
    for version in VERSIONS {
        let name = service(version);
        let there = skyward_binder::hidl::find(hardware, &name, INSTANCE).with_context(|| format!("look for {name}"))?;
        if there.is_some() {
            found.push(format!("{name}/{INSTANCE}"));
        }
    }
    Ok(found)
}

/// Reach the running key service, or say that none is.
#[cfg(target_os = "android")]
pub fn open(hardware: &skyward_binder::driver::Binder) -> Result<skyward_binder::driver::Handle<'_>> {
    skyward_binder::hidl::find(hardware, SERVICE, INSTANCE)?
        .with_context(|| format!("{SERVICE}/{INSTANCE} is not registered; the phone's key service has to be started first"))
}

/// What the service says it serves, which changes nothing and is what to
/// ask to see that it answers at all.
#[cfg(target_os = "android")]
pub fn describes(device: &skyward_binder::driver::Handle) -> Result<String> {
    skyward_binder::hidl::describes(device)
}

/// What the service says about itself.
#[cfg(target_os = "android")]
pub fn hardware(device: &skyward_binder::driver::Handle) -> Result<Hardware> {
    let what = "ask the key service about itself";
    let reply = device.transact(GET_HARDWARE_INFO, &Message::call(CALLER)).context(what)?;
    let mut read = Answer::new(reply.bytes());
    read.status().context(what)?;
    let security_level = read.i32().context("read how strongly the key service is protected")?;
    let name = string(&mut read).context("read what the key service calls itself")?;
    let author = string(&mut read).context("read who wrote the key service")?;
    Ok(Hardware { security_level, name, author })
}

/// A string as the older kind hands it over: a frame, then the characters.
fn string(read: &mut Answer) -> Result<String> {
    let frame = read.pointed().context("read the frame of a string")?;
    if frame.len() < FRAME_BYTES {
        bail!("the string's frame is {} bytes, not {FRAME_BYTES}", frame.len());
    }
    let characters = read.pointed().context("read the characters of a string")?;
    let text = characters.strip_suffix(&[0]).unwrap_or(characters);
    Ok(String::from_utf8_lossy(text).into_owned())
}

/// What the service says a key may be used for: each entry a tag, and the
/// number or length that came with it.
///
/// This asks about a key the service already holds a wrapping for and
/// changes nothing about it.
#[cfg(target_os = "android")]
pub fn characteristics(device: &skyward_binder::driver::Handle, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<Use>> {
    let what = "ask what the key may be used for";
    let reply = device.transact(GET_KEY_CHARACTERISTICS, &uses(key_blob, app_id)).context(what)?;
    let mut read = Answer::new(reply.bytes());
    read.status().context(what)?;
    read.i32().context("read whether the service took the question")?;
    let mut out = Vec::new();
    // The answer is two lists of parameters the same shape, one the
    // service keeps in software and one the secure world enforces.
    for _ in 0..2 {
        let list = read.pointed().context("read the frame of a list of parameters")?;
        if list.len() < FRAME_BYTES {
            bail!("the list's frame is {} bytes, not {FRAME_BYTES}", list.len());
        }
        let count = u32::from_le_bytes(list[8..12].try_into().expect("four bytes"));
        for _ in 0..count {
            let entry = read.pointed().context("read a parameter of the list")?;
            let mut fields = Fields::of(entry);
            let tag = fields.i32()?;
            fields.take(4).context("step over the parameter's alignment")?;
            let value = fields.u64()?;
            out.push(Use { tag, value: value as i64, raw: entry.to_vec() });
        }
    }
    Ok(out)
}

/// One entry of what a key may be used for, as it came back: the tag, the
/// number that came with it, and the bytes it lay in.
pub struct Use {
    pub tag: i32,
    pub value: i64,
    pub raw: Vec<u8>,
}

/// The call that asks what a key may be used for. What the key is bound to
/// is named as the application id Android bound it to, which for the key
/// of the data partition is the hash of the directory it came from and
/// nothing else.
pub fn uses(key_blob: &[u8], app_id: &[u8]) -> Message {
    let mut call = Message::call(CALLER);
    call.bytes(key_blob);
    call.bytes(app_id);
    call.bytes(&[]);
    call
}

/// Send a call and give back exactly what came back, for reading by hand
/// while the shape of an answer is still being learnt.
#[cfg(target_os = "android")]
pub fn ask(device: &skyward_binder::driver::Handle, code: u32, call: &Message) -> Result<Vec<u8>> {
    Ok(device.transact(code, call)?.bytes().to_vec())
}

/// The older key service, as this program uses it to unwrap a key: the
/// operations the newer kind calls `begin`, `update` and `finish`, over the
/// layout that carries whole structures by address.
///
/// The way a key's bytes are unwrapped here is the way the release of
/// Android that wrote them unwraps it — vold's own `KeyStorage`: a
/// decryption is opened on the key blob with the length of its tag and the
/// application id it is bound to, the bytes the key is held in are fed to
/// it without the nonce in front, and what it gives back is the key.
pub struct Keymaster<'a> {
    device: skyward_binder::driver::Handle<'a>,
}

/// A decryption the service has opened, which has to be closed again
/// whether it is finished or dropped.
struct Operation<'a> {
    device: &'a skyward_binder::driver::Handle<'a>,
    handle: u64,
}

/// How long the tag on what the service keeps for the data partition is.
const MAC_BYTES: i32 = 128;

/// The tag that says how long the tag of an authenticated encryption is.
const TAG_MAC_LENGTH: u32 = 805_307_371;
/// The tag that says what a key is bound to.
const TAG_APPLICATION_ID: u32 = -1_879_047_591i32 as u32;
/// The tag that says the nonce an operation runs under.
const TAG_NONCE: u32 = -1_879_047_191i32 as u32;

/// What the service takes for a purpose: it decrypts, which is what
/// unwrapping a key is here.
const PURPOSE_DECRYPT: i32 = 1;

/// What the service says when the key was made under an older build of the
/// phone's own firmware and must be renewed before use.
const KEY_REQUIRES_UPGRADE: i32 = -62;

/// How many bytes of the stored key are its nonce, and how many its tag.
const NONCE_BYTES: usize = 12;

#[derive(Debug)]
struct Refused(i32);

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the older key service refused with its code {}", self.0)
    }
}

impl std::error::Error for Refused {}

impl<'a> Keymaster<'a> {
    /// Reach the older key service, whichever version of it the phone
    /// carries, and say which one it is.
    #[cfg(target_os = "android")]
    pub fn open(hardware: &'a skyward_binder::driver::Binder) -> Result<Keymaster<'a>> {
        let (device, version) = Self::find(hardware)?;
        let _ = version;
        Ok(Keymaster { device })
    }

    /// The newest version of the older key service the phone has
    /// registered.
    #[cfg(target_os = "android")]
    fn find(hardware: &'a skyward_binder::driver::Binder) -> Result<(skyward_binder::driver::Handle<'a>, String)> {
        let mut looked = Vec::new();
        for version in VERSIONS {
            let name = service(version);
            match skyward_binder::hidl::find(hardware, &name, INSTANCE) {
                Ok(Some(device)) => return Ok((device, name)),
                Ok(None) => looked.push(format!("{name} is not registered")),
                Err(e) => looked.push(format!("{name}: {e:#}")),
            }
        }
        bail!("the phone runs none of the older key services: {}", looked.join("; "))
    }

    /// What the service says it serves, which changes nothing.
    #[cfg(target_os = "android")]
    pub fn describes(&self) -> Result<String> {
        skyward_binder::hidl::describes(&self.device)
    }

    /// What the service says about itself.
    #[cfg(target_os = "android")]
    pub fn hardware(&self) -> Result<Hardware> {
        let what = "ask the older key service about itself";
        let reply = self.device.transact(GET_HARDWARE_INFO, &Message::call(CALLER)).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        let security_level = read.i32().context("read how strongly the older key service is protected")?;
        let name = string(&mut read).context("read what the older key service calls itself")?;
        let author = string(&mut read).context("read who wrote the older key service")?;
        Ok(Hardware { security_level, name, author })
    }

    /// Undo the encryption a key was held closed with, and give the key.
    /// `app_id` is what the key was bound to when it was made, and the
    /// bytes are the stored form: the nonce in front, then what the
    /// service encrypted with the tag behind it.
    #[cfg(target_os = "android")]
    pub fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> Result<Vec<u8>> {
        match self.open_operation(key_blob, app_id, nonce) {
            Ok(operation) => self.feed(operation, body),
            Err(e) if e.downcast_ref::<Refused>().is_some_and(|r| r.0 == KEY_REQUIRES_UPGRADE) => {
                let renewed = self.upgrade(key_blob, app_id)?;
                let operation = self.open_operation(&renewed, app_id, nonce)?;
                self.feed(operation, body)
            }
            Err(e) => Err(e),
        }
    }

    /// Feed the bytes to the operation and close it, giving what it gave
    /// back. Every call gives back what it would and says how much of its
    /// input it took, which need not be all of it.
    #[cfg(target_os = "android")]
    fn feed(&self, operation: Operation<'_>, body: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut left = body;
        // A call that takes nothing would be one that never ends, so what
        // is left is only ever fed again when the last call took some.
        while !left.is_empty() {
            let (taken, given) = self.update(&operation, left)?;
            ensure!(taken > 0, "the key service took none of the {} bytes it was given", left.len());
            out.extend_from_slice(&given);
            left = &left[taken..];
        }
        out.extend_from_slice(&self.finish(&operation)?);
        Ok(out)
    }

    /// Open a decryption on the key, with the parameters the release of
    /// Android that wrote the key gives it.
    #[cfg(target_os = "android")]
    fn open_operation(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8]) -> Result<Operation<'_>> {
        let what = "start a decryption with the older key service";
        let mut call = Message::call(CALLER);
        call.i32(PURPOSE_DECRYPT);
        call.bytes(key_blob);
        // What the service is told about how the key is used: the length of
        // its tag, what it is bound to, and the nonce the bytes carry.
        let mut params = vec![Param::Integer { tag: TAG_MAC_LENGTH, value: MAC_BYTES as u64 }];
        if !app_id.is_empty() {
            params.push(Param::Blob { tag: TAG_APPLICATION_ID, bytes: app_id.to_vec() });
        }
        params.push(Param::Blob { tag: TAG_NONCE, bytes: nonce.to_vec() });
        call.parameters(&params);
        // A key the data partition is kept closed with is guarded by
        // nothing the screen lock holds, so no note of an answered screen
        // lock goes with it.
        token(&mut call);
        let reply = self.device.transact(BEGIN, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        let code = read.i32().context("read whether the older key service started a decryption")?;
        if code != 0 {
            return Err(Refused(code).into());
        }
        read.run().context("step over the parameters the decryption came back with")?;
        let handle = read.u64().context("read the decryption the service opened")?;
        ensure!(handle != 0, "the older key service opened no decryption");
        Ok(Operation { device: &self.device, handle })
    }

    /// Renew a key blob for the firmware running now. The metadata wrapping
    /// key is bound only to its application id, which must be supplied again.
    #[cfg(target_os = "android")]
    fn upgrade(&self, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<u8>> {
        let what = "renew the key for the older key service's current firmware";
        let mut call = Message::call(CALLER);
        call.bytes(key_blob);
        let params = if app_id.is_empty() {
            Vec::new()
        } else {
            vec![Param::Blob { tag: TAG_APPLICATION_ID, bytes: app_id.to_vec() }]
        };
        call.parameters(&params);
        let reply = self.device.transact(UPGRADE_KEY, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        let code = read.i32().context("read whether the key was renewed")?;
        if code != 0 {
            return Err(Refused(code).into());
        }
        Ok(read.vector().context("read the renewed key")?.to_vec())
    }

    #[cfg(target_os = "android")]
    fn update(&self, operation: &Operation<'_>, input: &[u8]) -> Result<(usize, Vec<u8>)> {
        let what = "feed the decryption";
        let mut call = Message::call(CALLER);
        call.u64(operation.handle);
        // Nothing more is said about the operation, and no note of an
        // answered screen lock is carried.
        call.parameters(&[]);
        call.bytes(input);
        token(&mut call);
        verification(&mut call);
        let reply = operation.device.transact(UPDATE, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        let code = read.i32().context("read whether the decryption took the bytes")?;
        if code != 0 {
            return Err(Refused(code).into());
        }
        let taken = read.i32().context("read how much of the bytes the decryption took")?;
        read.run().context("step over the parameters the decryption came back with")?;
        let out = read.vector().context("read what the decryption gave back")?.to_vec();
        Ok((taken.max(0) as usize, out))
    }

    #[cfg(target_os = "android")]
    fn finish(&self, operation: &Operation<'_>) -> Result<Vec<u8>> {
        let what = "close the decryption, which is where a wrong key is refused";
        let mut call = Message::call(CALLER);
        call.u64(operation.handle);
        call.parameters(&[]);
        call.bytes(&[]);
        call.bytes(&[]);
        token(&mut call);
        verification(&mut call);
        let reply = operation.device.transact(FINISH, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        let code = read.i32().context("read whether the decryption ended")?;
        if code != 0 {
            return Err(Refused(code).into());
        }
        read.run().context("step over the parameters the decryption ended with")?;
        Ok(read.vector().context("read what the decryption ended with")?.to_vec())
    }

    /// Drop a decryption without finishing it, which tells whether the key
    /// could be unwrapped at all: opening one and dropping it changes
    /// nothing of what the phone holds.
    #[cfg(target_os = "android")]
    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> Result<()> {
        let operation = self.open_operation(key_blob, app_id, &[0; NONCE_BYTES])?;
        let what = "drop the decryption";
        let mut call = Message::call(CALLER);
        call.u64(operation.handle);
        let reply = operation.device.transact(ABORT, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        let code = read.i32().context("read whether the decryption was dropped")?;
        if code != 0 {
            return Err(Refused(code).into());
        }
        Ok(())
    }
}

/// An empty note of an answered screen lock: the key the data partition is
/// kept closed with is guarded by nothing the lock holds.
fn token(call: &mut Message) {
    // Three u64 fields, a four-byte authenticator type, four bytes of
    // alignment, a u64 timestamp, then the 16-byte MAC vector: 56 bytes.
    call.structure_with(vec![0; 56], vec![(40, Vec::new(), 0)]);
}

/// An empty note of what another secure world checked: this program has
/// asked nothing of one.
fn verification(call: &mut Message) {
    // Challenge, timestamp, a vector of parameters, security level plus
    // padding, and the MAC vector: 56 bytes. Both vectors are empty but
    // still registered as embedded buffers so their pointers are valid.
    call.structure_with(vec![0; 56], vec![(16, Vec::new(), 0), (40, Vec::new(), 0)]);
}

/// A stretch of bytes as the older kind holds one: a cursor that walks it
/// field by field.
struct Fields<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    fn of(bytes: &'a [u8]) -> Fields<'a> {
        Fields { bytes, at: 0 }
    }

    fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().expect("four bytes")))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes")))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at + n;
        if end > self.bytes.len() {
            bail!("the value holds {} bytes, {n} more were read at {}", self.bytes.len(), self.at);
        }
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }
}
