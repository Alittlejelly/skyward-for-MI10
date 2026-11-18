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

use anyhow::{bail, Context, Result};
use skyward_binder::hidl::{Answer, Message};

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
