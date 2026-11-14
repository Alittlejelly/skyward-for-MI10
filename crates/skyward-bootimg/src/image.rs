use abootimg_oxide::{binrw::io::Cursor, Header, HeaderV0Versioned};
use anyhow::{anyhow, Context, Result};
use sha1::{Digest, Sha1};
use std::fs;
use std::path::Path;

/// A boot image split into its parts. Header version 3 or 4 names only a
/// kernel and a ramdisk, as `boot`, `init_boot` and the `recovery` of a phone
/// that keeps none of its own carry. Version 0 to 2 adds the second stage,
/// the recovery DTBO and the device tree, which a `recovery` partition of its
/// own carries beside its kernel, as the Mi 10's does; the bootloader starts
/// nothing without the DTBO that describes its hardware.
pub struct BootImage {
    pub header: Header,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    pub second: Vec<u8>,
    pub recovery_dtbo: Vec<u8>,
    pub dtb: Vec<u8>,
}

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    let end = at + len as usize;
    bytes.get(at..end).map(<[u8]>::to_vec).ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

/// `n` filled to the end of the page it is in.
fn round_up(n: usize, page: usize) -> usize {
    n.div_ceil(page) * page
}

impl BootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        BootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    /// The image `bytes` hold, as a partition holds it: the image, then
    /// whatever fills the partition after it.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = Header::parse(&mut Cursor::new(bytes)).context("header")?;
        let page = header.page_size();
        let kernel = section(bytes, header.kernel_position(), header.kernel_size(), "kernel")?;
        let ramdisk = section(bytes, header.ramdisk_position(), header.ramdisk_size(), "ramdisk")?;
        // The parts after the ramdisk, where a version 0 to 2 header names
        // them: the second stage, then the recovery DTBO at the offset it
        // gives, then the device tree.
        let (second, recovery_dtbo, dtb) = match &header {
            Header::V0(h) => {
                let second_size = h.second_bootloader_size;
                let second = section(bytes, header.ramdisk_position() + round_up(header.ramdisk_size() as usize, page), second_size, "second")?;
                match &h.versioned {
                    HeaderV0Versioned::V2 { recovery_dtbo_size, recovery_dtbo_addr, dtb_size, .. } => {
                        // Where the parts after the second stage lie: the
                        // image lays them out in pages, and a header that
                        // carries no DTBO of its own gives no offset for the
                        // one it does not have. The offset a header does give
                        // is where its own writer put it, which is that.
                        let at = match *recovery_dtbo_size {
                            0 => header.ramdisk_position() + round_up(header.ramdisk_size() as usize, page) + round_up(second_size as usize, page),
                            _ => *recovery_dtbo_addr as usize,
                        };
                        let dtbo = section(bytes, at, *recovery_dtbo_size, "recovery dtbo")?;
                        let dtb = section(bytes, at + round_up(*recovery_dtbo_size as usize, page), *dtb_size, "dtb")?;
                        (second, dtbo, dtb)
                    }
                    _ => (second, Vec::new(), Vec::new()),
                }
            }
            Header::V3(_) => (Vec::new(), Vec::new(), Vec::new()),
        };
        Ok(BootImage { header, kernel, ramdisk, second, recovery_dtbo, dtb })
    }

    /// The image with sizes taken from its parts, laid out in the pages its
    /// header names, and the digest its header carries taken of those parts
    /// again. A version 4 header keeps its version but carries no boot
    /// signature; unlocked bootloaders do not ask for one. A version 0 to 2
    /// header keeps all else it holds, the addresses and the command line the
    /// bootloader reads, as the stock image wrote them.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut header = self.header.clone();
        let page = header.page_size();
        let kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
        let ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
        match &mut header {
            Header::V0(h) => {
                h.kernel_size = kernel_size;
                h.ramdisk_size = ramdisk_size;
                h.second_bootloader_size = u32::try_from(self.second.len()).context("second size")?;
                if let HeaderV0Versioned::V2 { recovery_dtbo_size, recovery_dtbo_addr, dtb_size, .. } = &mut h.versioned {
                    *recovery_dtbo_size = u32::try_from(self.recovery_dtbo.len()).context("dtbo size")?;
                    *dtb_size = u32::try_from(self.dtb.len()).context("dtb size")?;
                    // The DTBO goes after the second stage, at the offset the
                    // header gives rather than an address to load at; the
                    // header itself takes the first page.
                    *recovery_dtbo_addr = (page
                        + round_up(kernel_size as usize, page)
                        + round_up(ramdisk_size as usize, page)
                        + round_up(self.second.len(), page)) as u64;
                }
                let digest = boot_id(&[&self.kernel, &self.ramdisk, &self.second, &self.recovery_dtbo, &self.dtb]);
                h.hash_digest = [0; 32];
                h.hash_digest[..digest.len()].copy_from_slice(&digest);
            }
            Header::V3(h) => {
                h.kernel_size = kernel_size;
                h.ramdisk_size = ramdisk_size;
                h.v4_signature_size = h.v4_signature_size.map(|_| 0);
            }
        }
        let mut out = Vec::new();
        header.write(&mut out).context("write header")?;
        pad(&mut out, page);
        for part in [&self.kernel, &self.ramdisk, &self.second, &self.recovery_dtbo, &self.dtb] {
            out.extend_from_slice(part);
            pad(&mut out, page);
        }
        Ok(out)
    }
}

/// The digest a version 0 to 2 header carries of the parts after it: SHA-1 of
/// each part and the size the header gives it, in the order the image lays
/// them out, as mkbootimg takes it.
fn boot_id(parts: &[&Vec<u8>]) -> [u8; 20] {
    let mut sha = Sha1::new();
    for part in parts {
        sha.update(part);
        sha.update((part.len() as u32).to_le_bytes());
    }
    sha.finalize().into()
}

/// Fill `out` to the end of the page it is in.
fn pad(out: &mut Vec<u8>, page: usize) {
    out.resize(out.len().div_ceil(page) * page, 0);
}
