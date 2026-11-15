use anyhow::{bail, Context, Result};
use procfs::process::{FDTarget, MMapPath, Process};
use skyward_config::Service;
use skyward_sys::ueventd;
use skyward_vab::Mounted;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Whether a program runs inside the installed system's tree, put together
/// where the system's own mount table puts its partitions.
fn needs_root(services: &[Service]) -> bool {
    services.iter().any(|s| s.root.is_some())
}

/// Put the mounted partitions where the installed system's own mount table
/// puts them, under a folder of the recovery's, and give that folder as the
/// tree of every program that asks for it. A partition that did not mount
/// is left out: a program that reads it says so itself.
pub fn prepare_root() -> Result<()> {
    let root = Path::new(INSTALLED_ROOT);
    for dir in ["system", "system_ext", "vendor", "product", "odm", "mi_ext", "apex", "dev", "proc", "sys", "mnt/vendor/persist"] {
        let at = root.join(dir);
        fs::create_dir_all(&at).with_context(|| format!("make {}", at.display()))?;
    }
    // The tree is made by the recovery, which keeps what it makes to itself:
    // a program run as one of the phone's own accounts has to be able to walk
    // through it to reach what it runs, and is refused the whole tree
    // otherwise, at the first step.
    for dir in std::iter::once("").chain(["system", "system_ext", "vendor", "product", "odm", "mi_ext", "apex", "dev", "proc", "sys", "mnt", "mnt/vendor", "mnt/vendor/persist"]) {
        let at = if dir.is_empty() { root.to_path_buf() } else { root.join(dir) };
        let _ = fs::set_permissions(&at, fs::Permissions::from_mode(0o755));
    }
    let parts = [
        ("/mnt/system/system", "system"),
        ("/vendor", "vendor"),
        ("/mnt/product", "product"),
        ("/mnt/system_ext", "system_ext"),
        ("/odm", "odm"),
        ("/mnt/mi_ext", "mi_ext"),
        ("/dev", "dev"),
        ("/proc", "proc"),
        ("/sys", "sys"),
        ("/mnt/vendor/persist", "mnt/vendor/persist"),
    ];
    for (from, into) in parts {
        let from = Path::new(from);
        if !from.is_dir() {
            continue;
        }
        bind(from, &root.join(into))?;
    }
    // The devices of the binder are children of a mount of their own: a bind
    // of the folder they are named in does not bring what is mounted under
    // it, and a program that talks over the binder finds nothing without it.
    if Path::new("/dev/binderfs").is_dir() {
        let at = root.join("dev/binderfs");
        fs::create_dir_all(&at).ok();
        bind(Path::new("/dev/binderfs"), &at)?;
    }
    // Each bundle of the system's own programs is a mount of its own too.
    if let Ok(entries) = fs::read_dir("/apex") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let at = root.join("apex").join(&name);
            if fs::create_dir_all(&at).is_err() {
                continue;
            }
            bind(&Path::new("/apex").join(&name), &at)?;
        }
    }
    Ok(())
}

/// Mount `from` on the folder `into`, which is already there. A folder that
/// already has something mounted on it is left as it is: the recovery may
/// come up again over a tree an earlier run put together.
fn bind(from: &Path, into: &Path) -> Result<()> {
    if on_mount_table(into) {
        return Ok(());
    }
    let source = std::ffi::CString::new(from.as_os_str().as_bytes()).context("a NUL in the path")?;
    let target = std::ffi::CString::new(into.as_os_str().as_bytes()).context("a NUL in the path")?;
    let done = unsafe { libc::mount(source.as_ptr(), target.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) };
    if done != 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("mount {} on {}", from.display(), into.display()));
    }
    Ok(())
}

/// Whether something is mounted on `path`.
fn on_mount_table(path: &Path) -> bool {
    let Some(wanted) = path.to_str() else { return false };
    fs::read_to_string("/proc/mounts").is_ok_and(|table| table.lines().any(|line| line.split_whitespace().nth(1) == Some(wanted)))
}

/// Take back the folders put together for the installed system's tree.
///
/// A partition bound into that tree is held by it: unmounting the
/// partition itself takes the partition off its own mount point, but the
/// device under it stays in use for as long as the bound copy is there,
/// and the device-mapper device it was reached through will not go while
/// it is. Each copy therefore leaves the tree too, and leaves it at once
/// rather than waiting to be let go: the programs running from the tree
/// keep what they have open, and their pages are locked in memory by then.
pub fn release_root() -> Result<()> {
    let root = Path::new(INSTALLED_ROOT);
    let mut into: Vec<PathBuf> = vec![
        "dev/binderfs".into(),
        "mnt/vendor/persist".into(),
        "sys".into(),
        "proc".into(),
        "dev".into(),
        "mi_ext".into(),
        "odm".into(),
        "system_ext".into(),
        "product".into(),
        "vendor".into(),
        "system".into(),
    ];
    // Each bundle of the system's own programs was bound one by one.
    if let Ok(entries) = fs::read_dir("/apex") {
        into.extend(entries.flatten().map(|e| Path::new("apex").join(e.file_name())));
    }
    for dir in into {
        let at = root.join(&dir);
        if !on_mount_table(&at) {
            continue;
        }
        let target = std::ffi::CString::new(at.as_os_str().as_bytes()).context("a NUL in the path")?;
        if unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) } != 0 {
            return Err(io::Error::last_os_error()).with_context(|| format!("take {} out of the tree", at.display()));
        }
    }
    Ok(())
}



/// A program that ends sooner than this after starting waits this long
/// before it is started again.
const RESTART_DELAY: Duration = Duration::from_secs(1);

/// How long a program gets to become what it says it will be.
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const READY_POLL: Duration = Duration::from_millis(100);

/// Where the kernel says the highest capability it knows.
const CAP_LAST_CAP: &str = "/proc/sys/kernel/cap_last_cap";

/// Where what a program says about itself is kept: a recovery throws that
/// away otherwise, and a program that will not start says why only there.
const PROGRAM_LOGS: &str = "/skyward/log";

/// The tree a program of the installed system is given as its own: the
/// partitions the recovery mounted, put where that system's own mount table
/// puts them, so that the paths it was built with name what they name on the
/// phone. It is made under the recovery's own folder, which is writable,
/// since the system's partitions are read only.
const INSTALLED_ROOT: &str = "/skyward/root";

/// The version of the kernel's capability sets that holds 64 of them.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Keep each program running, one thread per program: start it, and start
/// it again whenever it exits. They are started in the order they are
/// written, and one that says what it will be ready with holds up those
/// after it until it is. A program still running from an earlier instance
/// of the recovery service is waited on instead of started twice. A
/// program that runs once is run to its end where it stands in that order.
/// Each runs as the user, in the groups and with the capabilities the
/// phone's own init gives it.
///
/// `libraries` is a directory of shared libraries every one of them may
/// need, searched after whatever it names itself.
pub fn start(services: &[Service], libraries: &[PathBuf]) -> Result<()> {
    let known = ueventd::accounts(&ueventd::PASSWD_FILES.iter().chain(&ueventd::GROUP_FILES).copied().collect::<Vec<_>>());
    if needs_root(services) {
        prepare_root().context("put the installed system's tree together")?;
    }
    // The socket the chip's housekeeping serves on lives under the folder
    // the data partition keeps for the sockets of the wireless services;
    // the daemon binds it as it starts, before anything asks it to work,
    // so the folder is made here, where the services are made ready.
    let _ = fs::create_dir_all("/data/vendor/wifi/sockets");
    for s in services {
        if !Path::new(&s.path).is_file() {
            // One the phone's build does not carry, or one on a partition
            // that did not mount: the services after it still start.
            skyward_sys::kmsg(&format!("{} is missing; is its partition mounted?", s.path))?;
            continue;
        }
        let mut s = s.clone();
        // The libraries the phone's own programs were built against come
        // before the ones a device names: a name in the device's list is a
        // folder the recovery keeps, not a preference over the interface. A
        // program the installed system carries was built against that
        // system's libraries alone, and is given those alone.
        let mut ordered: Vec<String> = if s.own_libraries {
            Vec::new()
        } else {
            libraries.iter().map(|d| d.to_string_lossy().into_owned()).collect()
        };
        ordered.extend(s.libraries.iter().cloned());
        s.libraries = ordered;
        let who = Credentials::of(&s, &known)?;
        if s.oneshot {
            let status = command(&s, &who)?.status().with_context(|| format!("run {}", s.path))?;
            // A script the phone's own init runs once is a setting up of
            // things the recovery does not need: one that fails leaves the
            // services after it to start, as the phone's own init would.
            if status.success() {
                skyward_sys::kmsg(&format!("ran {} {}", s.path, s.args.join(" ")))?;
            } else {
                skyward_sys::kmsg(&format!("{} {} ended: {status}", s.path, s.args.join(" ")))?;
            }
            continue;
        }
        let waiting = s.clone();
        let name = Path::new(&s.path).file_name().map_or_else(|| s.path.clone(), |n| n.to_string_lossy().into_owned());
        thread::Builder::new().name(name).spawn(move || supervise(&s, &who)).context("start a supervising thread")?;
        ready(&waiting)?;
    }
    Ok(())
}

/// Who a program runs as and what of root's it keeps, as the phone's own
/// init has it run, worked out before it is started: between the fork and
/// the exec nothing may be looked up.
#[derive(Debug, Clone)]
struct Credentials {
    uid: libc::uid_t,
    gid: libc::gid_t,
    /// The other groups it is in.
    groups: Vec<libc::gid_t>,
    kept: Option<Kept>,
}

/// The capabilities a program keeps, as masks.
#[derive(Debug, Clone, Copy)]
struct Kept {
    mask: u64,
    /// Those and the right to drop the others for good, which goes once
    /// they are dropped.
    dropping: u64,
    /// The highest capability the kernel knows.
    last: u32,
}

impl Credentials {
    /// Who `s` runs as, by the names the phone gives its accounts: root,
    /// in no other group, keeping all of root's, where it names none.
    fn of(s: &Service, known: &HashMap<String, u32>) -> Result<Self> {
        let id = |name: &String| ueventd::account(known, name).with_context(|| format!("{}: the phone has no account named {name}", s.path));
        let uid = s.user.as_ref().map(id).transpose()?.unwrap_or(0);
        let mut groups = s.groups.iter().map(id).collect::<Result<Vec<_>>>()?;
        let gid = if groups.is_empty() { 0 } else { groups.remove(0) };
        let kept = if s.capabilities.is_empty() {
            None
        } else {
            let bit = |name: &str| skyward_config::capability(name).map(|n| 1u64 << n).with_context(|| format!("{}: {name} is not a capability", s.path));
            let mask = s.capabilities.iter().try_fold(0, |mask, c| bit(c).map(|b| mask | b))?;
            let last = fs::read_to_string(CAP_LAST_CAP).with_context(|| format!("read {CAP_LAST_CAP}"))?;
            let last = last.trim().parse().with_context(|| format!("read the number in {CAP_LAST_CAP}"))?;
            Some(Kept { mask, dropping: mask | bit("SETPCAP")?, last })
        };
        Ok(Self { uid, gid, groups, kept })
    }

    /// Become who the program runs as, in the child about to run it, as
    /// init does: take its groups and its user, keeping the capabilities
    /// through the change where it keeps some, then drop every other one
    /// for good and hand those it keeps on through the exec.
    fn take_on(&self) -> io::Result<()> {
        let done = |r: libc::c_int| if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) };
        let prctl = |option: libc::c_int, a: libc::c_ulong, b: libc::c_ulong| done(unsafe { libc::prctl(option, a, b, 0 as libc::c_ulong, 0 as libc::c_ulong) });
        if self.kept.is_some() {
            prctl(libc::PR_SET_KEEPCAPS, 1, 0)?;
        }
        done(unsafe { libc::setgroups(self.groups.len(), self.groups.as_ptr()) })?;
        done(unsafe { libc::setresgid(self.gid, self.gid, self.gid) })?;
        done(unsafe { libc::setresuid(self.uid, self.uid, self.uid) })?;
        let Some(kept) = self.kept else { return Ok(()) };
        set_capabilities(kept.dropping)?;
        for cap in (0..=kept.last).filter(|c| kept.mask & 1 << c == 0) {
            prctl(libc::PR_CAPBSET_DROP, cap.into(), 0)?;
        }
        set_capabilities(kept.mask)?;
        for cap in (0..=kept.last).filter(|c| kept.mask & 1 << c != 0) {
            prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong, cap.into())?;
        }
        Ok(())
    }
}

/// Make `mask` the capabilities the process has, may take up and hands on.
fn set_capabilities(mask: u64) -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct Sets {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header { version: CAPABILITY_VERSION_3, pid: 0 };
    let half = |bits: u32| Sets { effective: bits, permitted: bits, inheritable: bits };
    let sets = [half(mask as u32), half((mask >> 32) as u32)];
    if unsafe { libc::syscall(libc::SYS_capset, &header, sets.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Wait until the program has what it says it will be ready with.
fn ready(s: &Service) -> Result<()> {
    let waited_on = match (&s.ready_property, &s.ready_service, &s.ready_hardware_service) {
        (Some(p), _, _) => format!("set no {p}"),
        (_, Some(n), _) => format!("registered no {n}"),
        (_, _, Some(n)) => format!("registered no {n}"),
        _ => return Ok(()),
    };
    let until = Instant::now() + READY_TIMEOUT;
    loop {
        if let Some(name) = &s.ready_property {
            if skyward_sys::prop(name).is_some_and(|v| !v.is_empty()) {
                return Ok(());
            }
        }
        // Either directory may itself be starting again, and until it
        // answers nothing can be looked up in it.
        if let Some(name) = &s.ready_service {
            if registered(name) {
                return Ok(());
            }
        }
        if let Some(name) = &s.ready_hardware_service {
            if registered_hardware(name) {
                return Ok(());
            }
        }
        if Instant::now() >= until {
            bail!("{} {waited_on} in {} seconds", s.path, READY_TIMEOUT.as_secs());
        }
        thread::sleep(READY_POLL);
    }
}

fn supervise(s: &Service, who: &Credentials) -> ! {
    let mut quick = 0u32;
    loop {
        let started = Instant::now();
        let ended = match running(&s.path) {
            Some(pid) => wait_for(pid).map(|()| format!("pid {pid}, left by an earlier recovery service, exited")),
            None => run(s, who),
        };
        let line = match ended {
            Ok(how) => format!("{}: {how}", s.path),
            Err(e) => format!("{}: {e:#}", s.path),
        };
        let _ = skyward_sys::kmsg(&line);
        if started.elapsed() < RESTART_DELAY {
            // A program that stops as soon as it starts stops on the tenth
            // try too, and starting it again every second fills the kernel
            // log with the same line and keeps a core busy. The wait between
            // tries doubles until a minute: what it waits for may come up
            // meanwhile, and one that will not start at all is left alone.
            quick = quick.saturating_add(1);
            let wait = RESTART_DELAY.saturating_mul(1u32 << quick.min(6));
            thread::sleep(wait.min(Duration::from_secs(60)));
        } else {
            quick = 0;
        }
    }
}

/// Start the program and wait for it to end.
fn run(s: &Service, who: &Credentials) -> Result<String> {
    let mut child = command(s, who)?.spawn().with_context(|| format!("start {}", s.path))?;
    let status = child.wait().context("wait for it")?;
    Ok(format!("pid {} ended: {status}", child.id()))
}

/// The program as it is started: with what it is given, from the top of the
/// tree, reading and writing nothing of the recovery's, finding its
/// libraries where it names them, and as `who`. A program the installed
/// system carries is put inside that system's tree first, so that the paths
/// it was built with name what they name on the phone.
fn command(s: &Service, who: &Credentials) -> Result<Command> {
    let mut cmd = Command::new(&s.path);
    cmd.args(&s.args).current_dir("/").stdin(Stdio::null()).stdout(Stdio::null());
    // What a program says as it starts, and why it stops, goes to a file of
    // its own: a recovery keeps no log of its own, and a program that will
    // not start otherwise says nothing about it anywhere.
    let name = Path::new(&s.path).file_name().map_or_else(|| "program".into(), |n| n.to_string_lossy().into_owned());
    let _ = fs::create_dir_all(PROGRAM_LOGS);
    match fs::File::create(Path::new(PROGRAM_LOGS).join(format!("{name}.log"))) {
        Ok(log) => cmd.stderr(Stdio::from(log)),
        Err(_) => cmd.stderr(Stdio::null()),
    };
    if !s.libraries.is_empty() {
        cmd.env("LD_LIBRARY_PATH", s.libraries.join(":"));
    }
    let root = match &s.root {
        Some(path) => Some(std::ffi::CString::new(path.as_os_str().as_bytes()).context("a NUL in the path")?),
        None => None,
    };
    let who = who.clone();
    // Only system calls run between the fork and the exec, on what was
    // worked out before it.
    unsafe {
        cmd.pre_exec(move || {
            if let Some(root) = &root {
                // The tree first, while the program may still take it: once
                // it is who it runs as, it may not.
                if libc::chroot(root.as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::chdir(c_root()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            who.take_on()
        })
    };
    Ok(cmd)
}

/// The top of a tree, as a C string the child may use after the fork.
fn c_root() -> *const libc::c_char {
    c"/".as_ptr()
}

/// Lock in memory every file the running programs have mapped or open on
/// the `mounted` partitions, so they keep working once those partitions
/// are written over, and give the mount points the files are on. The
/// locked mappings stay for the rest of the recovery's life.
///
/// A program run inside the installed system's tree names that system's
/// files under the tree it was given as its own root, so a path says
/// nothing of which of the phone's partitions a file lies on: the program
/// that reads a library of the installed system calls it
/// /skyward/root/system_ext/lib64/…, and none of the partitions is mounted
/// there. What does say so is the filesystem the file lies on, which is
/// what is matched here.
pub fn pin(services: &[Service], mounted: &[Mounted]) -> Result<Vec<PathBuf>> {
    let mut files = BTreeSet::new();
    // A program run once has ended, and one between restarts has nothing in
    // memory to keep either.
    for s in services.iter().filter(|s| !s.oneshot) {
        let Some(pid) = running_in_tree(&s.path) else { continue };
        let process = Process::new(pid as i32).with_context(|| format!("open process {pid}"))?;
        for map in process.maps().with_context(|| format!("read the mappings of {}", s.path))? {
            if let MMapPath::Path(p) = map.pathname {
                files.insert(p);
            }
        }
        for fd in process.fd().with_context(|| format!("read the files {} has open", s.path))? {
            if let FDTarget::Path(p) = fd.with_context(|| format!("read a file {} has open", s.path))?.target {
                files.insert(p);
            }
        }
    }
    let partitions: Vec<(u64, &Mounted)> = mounted
        .iter()
        .filter_map(|m| fs::metadata(&m.mount_point).ok().map(|at| (at.dev(), m)))
        .collect();
    let mut busy: Vec<PathBuf> = Vec::new();
    for file in files {
        // A program may have let a file go between the reading of its
        // memory and this.
        let Ok(at) = fs::metadata(&file) else { continue };
        if !at.is_file() {
            continue;
        }
        let Some((_, m)) = partitions.iter().find(|(dev, _)| *dev == at.dev()) else { continue };
        lock(&file)?;
        let _ = skyward_sys::kmsg(&format!("kept {} in memory", file.display()));
        if !busy.contains(&m.mount_point) {
            busy.push(m.mount_point.clone());
        }
    }
    Ok(busy)
}

/// Map `path` whole and lock the mapping: its pages then stay in memory
/// for every process that maps the file.
fn lock(path: &Path) -> Result<()> {
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let len = file.metadata().with_context(|| format!("stat {}", path.display()))?.len() as usize;
    if len == 0 {
        return Ok(());
    }
    let at = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0) };
    if at == libc::MAP_FAILED {
        return Err(io::Error::last_os_error()).with_context(|| format!("map {}", path.display()));
    }
    if unsafe { libc::mlock(at, len) } != 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("lock {} in memory", path.display()));
    }
    Ok(())
}

/// Whether a service has registered. The service directory may itself be
/// starting again, and until it answers nothing is registered as far as
/// anyone can tell.
pub fn registered(name: &str) -> bool {
    match skyward_binder::driver::Binder::open() {
        Ok(binder) => matches!(skyward_binder::service::find(&binder, name), Ok(Some(_))),
        Err(_) => false,
    }
}

/// Whether a hardware service of the older kind has registered with the
/// directory its kind uses. It is named as the interface and then which of
/// them it is.
pub fn registered_hardware(name: &str) -> bool {
    let Some((interface, instance)) = name.rsplit_once('/') else { return false };
    match skyward_binder::driver::Binder::hardware() {
        Ok(binder) => matches!(skyward_binder::hidl::find(&binder, interface, instance), Ok(Some(_))),
        Err(_) => false,
    }
}

/// Whether the service directory takes calls. What it is asked about does
/// not matter; that it answers does.
pub fn reachable() -> bool {
    match skyward_binder::driver::Binder::open() {
        Ok(binder) => skyward_binder::service::find(&binder, "android.os.IServiceManager").is_ok(),
        Err(_) => false,
    }
}

/// A process already running `path`.
pub fn running(path: &str) -> Option<u32> {
    fs::read_dir("/proc").ok()?.flatten().find_map(|e| {
        let pid: u32 = e.file_name().to_str()?.parse().ok()?;
        (fs::read_link(e.path().join("exe")).ok()? == Path::new(path)).then_some(pid)
    })
}

/// The process running the program `path` names, whether it runs from where
/// the configuration names it or from inside the installed system's tree.
///
/// A program the recovery starts inside that tree is named there by the
/// tree, not by the configuration: the installed system keeps its own parts
/// where its own mount table puts them, so the program the configuration
/// calls /system/bin/hwservicemanager is the one the phone keeps under
/// system_ext. Only its name is the same in both, and a program of the
/// recovery's own has no part in that tree to be confused with.
fn running_in_tree(path: &str) -> Option<u32> {
    if let Some(pid) = running(path) {
        return Some(pid);
    }
    let named = Path::new(path).file_name()?;
    fs::read_dir("/proc").ok()?.flatten().find_map(|e| {
        let pid: u32 = e.file_name().to_str()?.parse().ok()?;
        let exe = fs::read_link(e.path().join("exe")).ok()?;
        (exe.file_name()? == named).then_some(pid)
    })
}

/// Wait for a process that is not our child to exit.
fn wait_for(pid: u32) -> Result<()> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        // It exited between being found and being opened.
        if e.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(e).context("open a pidfd");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    loop {
        if unsafe { libc::poll(&mut pfd, 1, -1) } >= 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e).context("wait on the pidfd");
        }
    }
}
