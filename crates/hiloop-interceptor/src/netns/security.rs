//! Irreversible confinement applied immediately before a workload or worker exec.

use nix::libc;
use std::{
    fs,
    io::{self, ErrorKind},
    os::fd::RawFd,
};

const FIRST_NON_STDIO_FD: RawFd = libc::STDERR_FILENO + 1;
const LAST_V3_CAPABILITY: u32 = 63;
const FIRST_UNREPRESENTABLE_V3_CAPABILITY: u32 = LAST_V3_CAPABILITY + 1;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

const LOCKED_SECUREBITS: libc::c_int = libc::SECBIT_NOROOT
    | libc::SECBIT_NOROOT_LOCKED
    | libc::SECBIT_NO_SETUID_FIXUP
    | libc::SECBIT_NO_SETUID_FIXUP_LOCKED
    | libc::SECBIT_KEEP_CAPS_LOCKED
    | libc::SECBIT_NO_CAP_AMBIENT_RAISE
    | libc::SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CloseRange {
    first: u32,
    last: u32,
}

/// Allocation-owning confinement plan prepared before entering a `pre_exec` closure.
///
/// File descriptors 0, 1, and 2 are always retained. `allowed_fds` names additional
/// descriptors and must be strictly increasing, unique, and at least 3. Preparation must
/// happen after all intentional descriptors are open. For a `Command` hook it must finish
/// before spawn; a direct-exec helper calls it from its ordinary single-threaded context.
#[derive(Debug, Clone)]
pub(super) struct ChildLockdown {
    descriptors: PreExecDescriptorSanitizer,
    last_capability: u32,
}

impl ChildLockdown {
    /// Validate inherited descriptors and discover bounds needed by the child-side fallback.
    pub(super) fn prepare(allowed_fds: &[RawFd]) -> io::Result<Self> {
        let descriptors = PreExecDescriptorSanitizer::prepare(allowed_fds)?;
        let last_capability = last_supported_capability()?;
        Ok(Self {
            descriptors,
            last_capability,
        })
    }

    /// Irreversibly remove privilege and unintended descriptors from the calling thread.
    ///
    /// This is allocation-free on success and is intended for a single-threaded re-exec
    /// helper immediately before its own direct `execve`. It must not run from
    /// `std::process::Command::pre_exec`, whose private exec-error descriptor is not visible
    /// to the caller; use [`Self::apply_in_pre_exec`] there. The caller must abort the child
    /// rather than continue when this returns an error.
    pub(super) fn apply(&self) -> io::Result<()> {
        self.drop_privileges()?;
        self.descriptors.close_unlisted()?;
        Ok(())
    }

    /// Irreversibly remove privilege and prevent unintended descriptors crossing a `Command` exec.
    ///
    /// Rust creates a private close-on-exec error descriptor after [`Self::prepare`] returns.
    /// This variant preserves that channel until a successful exec by marking every unlisted
    /// descriptor close-on-exec instead of closing it in the hook. It is allocation-free on
    /// success and must be the final `pre_exec` operation.
    pub(super) fn apply_in_pre_exec(&self) -> io::Result<()> {
        self.drop_privileges()?;
        self.descriptors.apply_in_pre_exec()?;
        Ok(())
    }

    fn drop_privileges(&self) -> io::Result<()> {
        set_locked_securebits()?;
        drop_bounding_capabilities(self.last_capability)?;
        clear_ambient_capabilities()?;
        set_no_new_privileges()?;
        clear_effective_permitted_inheritable_capabilities()?;
        Ok(())
    }
}

/// Descriptor-only sanitization prepared before entering a `pre_exec` closure.
///
/// The plan retains standard I/O and the sorted explicit allowlist. Every other descriptor is
/// marked close-on-exec, preserving Rust's private exec-error channel until exec succeeds. It does
/// not change credentials, capabilities, securebits, or `no_new_privs`.
#[derive(Debug, Clone)]
pub(super) struct PreExecDescriptorSanitizer {
    close_ranges: Vec<CloseRange>,
    fallback_last_fd: u32,
}

impl PreExecDescriptorSanitizer {
    /// Validate the allowlist and discover descriptor bounds before spawning a child.
    pub(super) fn prepare(allowed_fds: &[RawFd]) -> io::Result<Self> {
        Ok(Self {
            close_ranges: plan_close_ranges(allowed_fds)?,
            fallback_last_fd: fallback_last_fd()?,
        })
    }

    /// Mark every unlisted descriptor close-on-exec without changing process privilege.
    ///
    /// This is allocation-free on success and must be the final descriptor operation in a
    /// `pre_exec` closure.
    pub(super) fn apply_in_pre_exec(&self) -> io::Result<()> {
        mark_unlisted_descriptors_close_on_exec(&self.close_ranges, self.fallback_last_fd)
    }

    fn close_unlisted(&self) -> io::Result<()> {
        close_unlisted_descriptors(&self.close_ranges, self.fallback_last_fd)
    }
}

/// Prevent same-credential processes from inspecting the calling process.
///
/// Call this after the final exec and before exposing readiness because a later exec may reset the
/// dumpable attribute.
pub(super) fn deny_process_inspection() -> io::Result<()> {
    raw_prctl(libc::PR_SET_DUMPABLE, 0).map(|_| ())
}

/// Close every descriptor except standard I/O and a validated explicit allowlist.
///
/// This discovers descriptors and allocates, so it is only for the start of a single-threaded
/// re-exec helper. It must never be called from a post-fork `pre_exec` closure.
pub(super) fn close_descriptors_except(allowed_fds: &[RawFd]) -> io::Result<()> {
    PreExecDescriptorSanitizer::prepare(allowed_fds)?.close_unlisted()
}

/// Capability masks exported by Linux in `/proc/<pid>/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CapabilityStatus {
    inheritable: u64,
    permitted: u64,
    effective: u64,
    bounding: u64,
    ambient: u64,
}

impl CapabilityStatus {
    /// Parse all five capability masks without observing or changing process state.
    pub(super) fn parse_proc_status(status: &str) -> io::Result<Self> {
        let mut inheritable = None;
        let mut permitted = None;
        let mut effective = None;
        let mut bounding = None;
        let mut ambient = None;

        for line in status.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let destination = match name {
                "CapInh" => Some(&mut inheritable),
                "CapPrm" => Some(&mut permitted),
                "CapEff" => Some(&mut effective),
                "CapBnd" => Some(&mut bounding),
                "CapAmb" => Some(&mut ambient),
                _ => None,
            };
            if let Some(destination) = destination {
                parse_capability_field(destination, value)?;
            }
        }

        Ok(Self {
            inheritable: required_capability_field(inheritable)?,
            permitted: required_capability_field(permitted)?,
            effective: required_capability_field(effective)?,
            bounding: required_capability_field(bounding)?,
            ambient: required_capability_field(ambient)?,
        })
    }

    /// Read and parse the calling process's capability masks.
    pub(super) fn read_current() -> io::Result<Self> {
        Self::parse_proc_status(&fs::read_to_string("/proc/self/status")?)
    }

    /// Whether every capability set, including the bounding and ambient sets, is empty.
    pub(super) fn is_empty(self) -> bool {
        self.inheritable == 0
            && self.permitted == 0
            && self.effective == 0
            && self.bounding == 0
            && self.ambient == 0
    }

    pub(super) fn inheritable(self) -> u64 {
        self.inheritable
    }

    pub(super) fn permitted(self) -> u64 {
        self.permitted
    }

    pub(super) fn effective(self) -> u64 {
        self.effective
    }

    pub(super) fn bounding(self) -> u64 {
        self.bounding
    }

    pub(super) fn ambient(self) -> u64 {
        self.ambient
    }
}

fn parse_capability_field(destination: &mut Option<u64>, value: &str) -> io::Result<()> {
    if destination.is_some() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "duplicate capability field in /proc status",
        ));
    }
    let mut tokens = value.split_ascii_whitespace();
    let Some(mask) = tokens.next() else {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "empty capability field in /proc status",
        ));
    };
    if tokens.next().is_some() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "capability field in /proc status has trailing data",
        ));
    }
    *destination = Some(
        u64::from_str_radix(mask, 16)
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?,
    );
    Ok(())
}

fn required_capability_field(value: Option<u64>) -> io::Result<u64> {
    value.ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "missing capability field in /proc status",
        )
    })
}

fn plan_close_ranges(allowed_fds: &[RawFd]) -> io::Result<Vec<CloseRange>> {
    validate_allowed_fds(allowed_fds)?;

    let mut ranges = Vec::with_capacity(allowed_fds.len().saturating_add(1));
    let mut first = u32::try_from(FIRST_NON_STDIO_FD).map_err(|error| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid first non-stdio descriptor: {error}"),
        )
    })?;
    for &allowed_fd in allowed_fds {
        let allowed = u32::try_from(allowed_fd).map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!("invalid allowed descriptor: {error}"),
            )
        })?;
        if first < allowed {
            ranges.push(CloseRange {
                first,
                last: allowed - 1,
            });
        }
        first = allowed + 1;
    }

    let last_raw_fd = u32::try_from(RawFd::MAX).map_err(|error| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid raw descriptor maximum: {error}"),
        )
    })?;
    if first <= last_raw_fd {
        ranges.push(CloseRange {
            first,
            last: u32::MAX,
        });
    }
    Ok(ranges)
}

fn validate_allowed_fds(allowed_fds: &[RawFd]) -> io::Result<()> {
    let mut previous = None;
    for &fd in allowed_fds {
        if fd < FIRST_NON_STDIO_FD {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "allowed descriptors must be at least 3; stdio is implicit",
            ));
        }
        if previous.is_some_and(|previous| fd <= previous) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "allowed descriptors must be strictly sorted and unique",
            ));
        }
        previous = Some(fd);
    }
    Ok(())
}

fn parse_nr_open(value: &str) -> io::Result<u64> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
}

#[expect(
    unsafe_code,
    reason = "getrlimit writes one initialized rlimit value through a valid pointer; see SAFETY"
)]
fn fallback_last_fd() -> io::Result<u32> {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limits` is valid writable storage for exactly one `rlimit`; the call does not
    // retain the pointer, and its return value is checked before the fields are consumed.
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, std::ptr::from_mut(&mut limits)) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }

    let descriptor_limit = if limits.rlim_max == libc::RLIM_INFINITY {
        parse_nr_open(&fs::read_to_string("/proc/sys/fs/nr_open")?)?
    } else {
        limits.rlim_max
    };
    let last_raw_fd = u64::try_from(RawFd::MAX).map_err(|error| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("invalid raw descriptor maximum: {error}"),
        )
    })?;
    let mut highest = descriptor_limit.saturating_sub(1).min(last_raw_fd);

    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "non-UTF-8 descriptor name in /proc/self/fd",
            ));
        };
        let descriptor = file_name
            .parse::<u64>()
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
        highest = highest.max(descriptor.min(last_raw_fd));
    }

    u32::try_from(highest).map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
}

fn last_supported_capability() -> io::Result<u32> {
    let mut last = None;
    for capability in 0..=FIRST_UNREPRESENTABLE_V3_CAPABILITY {
        match raw_prctl(libc::PR_CAPBSET_READ, libc::c_ulong::from(capability)) {
            Ok(0 | 1) if capability <= LAST_V3_CAPABILITY => last = Some(capability),
            Ok(0 | 1) => {
                return Err(io::Error::new(
                    ErrorKind::Unsupported,
                    "kernel capability ABI exceeds Linux capability v3",
                ));
            }
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "PR_CAPBSET_READ returned an invalid value",
                ));
            }
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
                return last.ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::Unsupported,
                        "PR_CAPBSET_READ is unavailable for capability zero",
                    )
                });
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        ErrorKind::Unsupported,
        "kernel capability range could not be bounded",
    ))
}

fn set_locked_securebits() -> io::Result<()> {
    let current = raw_prctl(libc::PR_GET_SECUREBITS, 0)?;
    let securebits = desired_securebits(current);
    let securebits = libc::c_ulong::try_from(securebits)
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    raw_prctl(libc::PR_SET_SECUREBITS, securebits).map(|_| ())
}

fn desired_securebits(current: libc::c_int) -> libc::c_int {
    (current | LOCKED_SECUREBITS) & !libc::SECBIT_KEEP_CAPS
}

fn drop_bounding_capabilities(last_capability: u32) -> io::Result<()> {
    for capability in 0..=last_capability {
        raw_prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(capability))?;
    }
    Ok(())
}

fn clear_ambient_capabilities() -> io::Result<()> {
    let operation = libc::c_ulong::try_from(libc::PR_CAP_AMBIENT_CLEAR_ALL)
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    raw_prctl4(libc::PR_CAP_AMBIENT, operation, 0, 0, 0).map(|_| ())
}

fn set_no_new_privileges() -> io::Result<()> {
    raw_prctl(libc::PR_SET_NO_NEW_PRIVS, 1).map(|_| ())
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[expect(
    unsafe_code,
    reason = "capset is invoked with Linux v3 ABI structs of the required layout; see SAFETY"
)]
fn clear_effective_permitted_inheritable_capabilities() -> io::Result<()> {
    let header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let empty = [CapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: `_LINUX_CAPABILITY_VERSION_3` requires exactly two `CapabilityData` words.
    // Both pointers reference initialized, correctly aligned `repr(C)` values for the duration
    // of the syscall, and the kernel only reads them for `capset`.
    let result = unsafe {
        libc::syscall(
            libc::SYS_capset,
            std::ptr::from_ref(&header),
            empty.as_ptr(),
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn close_unlisted_descriptors(ranges: &[CloseRange], fallback_last_fd: u32) -> io::Result<()> {
    for &range in ranges {
        if close_range(range, 0).is_err()
            && let Some(fallback) = clipped_fallback_range(range, fallback_last_fd)
        {
            close_descriptor_loop(fallback)?;
        }
    }
    Ok(())
}

fn mark_unlisted_descriptors_close_on_exec(
    ranges: &[CloseRange],
    fallback_last_fd: u32,
) -> io::Result<()> {
    let flags = libc::c_ulong::from(libc::CLOSE_RANGE_CLOEXEC);
    for &range in ranges {
        if close_range(range, flags).is_err()
            && let Some(fallback) = clipped_fallback_range(range, fallback_last_fd)
        {
            mark_descriptor_loop_close_on_exec(fallback)?;
        }
    }
    Ok(())
}

fn clipped_fallback_range(range: CloseRange, fallback_last_fd: u32) -> Option<CloseRange> {
    let last = range.last.min(fallback_last_fd);
    (range.first <= last).then_some(CloseRange {
        first: range.first,
        last,
    })
}

#[expect(
    unsafe_code,
    reason = "close_range is a direct Linux syscall over an inclusive numeric range and scalar flags; see SAFETY"
)]
fn close_range(range: CloseRange, flags: libc::c_ulong) -> io::Result<()> {
    // SAFETY: `close_range` receives only integer values, no pointers. The planned range is
    // inclusive and ordered, and `flags` is either zero or `CLOSE_RANGE_CLOEXEC`. A failure is
    // reported through errno and triggers the matching per-descriptor fallback.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            libc::c_ulong::from(range.first),
            libc::c_ulong::from(range.last),
            flags,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[expect(
    unsafe_code,
    reason = "the pre-exec fallback inspects and updates descriptor flags with async-signal-safe fcntl; see SAFETY"
)]
fn mark_descriptor_loop_close_on_exec(range: CloseRange) -> io::Result<()> {
    let mut descriptor = range.first;
    loop {
        let Ok(raw_fd) = RawFd::try_from(descriptor) else {
            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        };
        // SAFETY: `F_GETFD` receives a plain descriptor and no variadic third argument. `fcntl`
        // is async-signal-safe and does not retain or access a Rust pointer.
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        if flags == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBADF) {
                return Err(error);
            }
        } else {
            // SAFETY: `F_SETFD` consumes the integer flag value immediately. The descriptor was
            // valid at `F_GETFD`, and the single-threaded child cannot close or replace it here.
            let result = unsafe { libc::fcntl(raw_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        if descriptor == range.last {
            return Ok(());
        }
        descriptor += 1;
    }
}

#[expect(
    unsafe_code,
    reason = "the fallback closes validated numeric descriptors with async-signal-safe close; see SAFETY"
)]
fn close_descriptor_loop(range: CloseRange) -> io::Result<()> {
    let mut descriptor = range.first;
    loop {
        let Ok(raw_fd) = RawFd::try_from(descriptor) else {
            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        };
        // SAFETY: `raw_fd` is a plain descriptor number in the precomputed close range. Linux
        // `close` and `fcntl(F_GETFD)` are async-signal-safe and neither call retains any pointer.
        // An error is verified with `fcntl` so a seccomp-denied close cannot silently leak the fd.
        let close_result = unsafe { libc::close(raw_fd) };
        if close_result == -1 {
            // SAFETY: `F_GETFD` accepts only the integer descriptor and command. It does not use
            // a variadic third argument or access Rust memory.
            let get_fd_result = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
            if get_fd_result != -1 {
                return Err(io::Error::from_raw_os_error(libc::EBUSY));
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBADF) {
                return Err(error);
            }
        }
        if descriptor == range.last {
            return Ok(());
        }
        descriptor += 1;
    }
}

fn raw_prctl(option: libc::c_int, argument: libc::c_ulong) -> io::Result<libc::c_int> {
    raw_prctl4(option, argument, 0, 0, 0)
}

#[expect(
    unsafe_code,
    reason = "prctl is called with scalar arguments for documented Linux process controls; see SAFETY"
)]
fn raw_prctl4(
    option: libc::c_int,
    argument2: libc::c_ulong,
    argument3: libc::c_ulong,
    argument4: libc::c_ulong,
    argument5: libc::c_ulong,
) -> io::Result<libc::c_int> {
    // SAFETY: all operations used by this module take scalar `unsigned long` arguments and no
    // pointers. Passing all four variadic arguments matches the Linux `prctl` syscall ABI.
    let result = unsafe { libc::prctl(option, argument2, argument3, argument4, argument5) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_ranges_preserve_stdio_and_sparse_allowlist() {
        assert_eq!(
            plan_close_ranges(&[3, 6, 7]).expect("valid allowlist"),
            [
                CloseRange { first: 4, last: 5 },
                CloseRange {
                    first: 8,
                    last: u32::MAX,
                },
            ]
        );
        assert_eq!(
            plan_close_ranges(&[]).expect("empty allowlist"),
            [CloseRange {
                first: 3,
                last: u32::MAX,
            }]
        );
    }

    #[test]
    fn close_ranges_do_not_cross_the_highest_allowed_descriptor() {
        assert_eq!(
            plan_close_ranges(&[RawFd::MAX]).expect("highest descriptor is valid"),
            [CloseRange {
                first: 3,
                last: u32::try_from(RawFd::MAX).expect("raw descriptor maximum fits") - 1,
            }]
        );
    }

    #[test]
    fn allowed_descriptors_must_be_extra_sorted_and_unique() {
        for invalid in [&[-1][..], &[0][..], &[2][..], &[4, 3][..], &[4, 4][..]] {
            let error = plan_close_ranges(invalid).expect_err("invalid allowlist");
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn fallback_ranges_are_clipped_without_touching_allowed_gaps() {
        assert_eq!(
            clipped_fallback_range(
                CloseRange {
                    first: 8,
                    last: u32::MAX,
                },
                12,
            ),
            Some(CloseRange { first: 8, last: 12 })
        );
        assert_eq!(
            clipped_fallback_range(
                CloseRange {
                    first: 8,
                    last: u32::MAX,
                },
                7,
            ),
            None
        );
    }

    #[test]
    #[expect(
        unsafe_code,
        reason = "the regression test installs the production async-signal-safe pre-exec descriptor hook; see SAFETY"
    )]
    fn descriptor_only_sanitizer_preserves_command_exec_error_reporting() {
        use std::{os::unix::process::CommandExt as _, process::Command};

        let sanitizer =
            PreExecDescriptorSanitizer::prepare(&[]).expect("descriptor sanitizer plan");
        let mut command = Command::new("/__hiloop_missing_exec_for_cloexec_test__");
        // SAFETY: the captured range plan is fully allocated before fork. The closure invokes
        // only the production `close_range`/`fcntl` path, which is async-signal-safe and retains
        // Rust's private close-on-exec error descriptor until the attempted exec reports ENOENT.
        unsafe {
            command.pre_exec(move || sanitizer.apply_in_pre_exec());
        }

        let error = command
            .spawn()
            .expect_err("missing executable must be reported by spawn");
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn securebits_lock_privilege_gain_and_force_keep_caps_off() {
        let current = libc::SECBIT_KEEP_CAPS | libc::SECBIT_EXEC_RESTRICT_FILE;
        let desired = desired_securebits(current);

        assert_eq!(desired & libc::SECBIT_KEEP_CAPS, 0);
        assert_ne!(desired & libc::SECBIT_KEEP_CAPS_LOCKED, 0);
        assert_ne!(desired & libc::SECBIT_NOROOT, 0);
        assert_ne!(desired & libc::SECBIT_NOROOT_LOCKED, 0);
        assert_ne!(desired & libc::SECBIT_NO_SETUID_FIXUP, 0);
        assert_ne!(desired & libc::SECBIT_NO_SETUID_FIXUP_LOCKED, 0);
        assert_ne!(desired & libc::SECBIT_NO_CAP_AMBIENT_RAISE, 0);
        assert_ne!(desired & libc::SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED, 0);
        assert_ne!(desired & libc::SECBIT_EXEC_RESTRICT_FILE, 0);
    }

    #[test]
    fn proc_status_capability_fields_parse_exactly() {
        let status = "\
Name:\tfixture\n\
CapInh:\t0000000000000001\n\
CapPrm:\t0000000000000002\n\
CapEff:\t0000000000000004\n\
CapBnd:\t000001ffffffffff\n\
CapAmb:\t0000000000000010\n\
NoNewPrivs:\t1\n";
        let parsed = CapabilityStatus::parse_proc_status(status).expect("valid proc status");

        assert_eq!(parsed.inheritable(), 1);
        assert_eq!(parsed.permitted(), 2);
        assert_eq!(parsed.effective(), 4);
        assert_eq!(parsed.bounding(), 0x0000_01ff_ffff_ffff);
        assert_eq!(parsed.ambient(), 16);
        assert!(!parsed.is_empty());
    }

    #[test]
    fn zero_proc_status_capabilities_are_empty() {
        let status = "\
CapInh:\t0000000000000000\n\
CapPrm:\t0000000000000000\n\
CapEff:\t0000000000000000\n\
CapBnd:\t0000000000000000\n\
CapAmb:\t0000000000000000\n";
        let parsed = CapabilityStatus::parse_proc_status(status).expect("valid proc status");
        assert!(parsed.is_empty());
    }

    #[test]
    fn proc_status_capability_parser_rejects_incomplete_or_ambiguous_input() {
        let invalid = [
            "CapInh: 0\nCapPrm: 0\nCapEff: 0\nCapBnd: 0\n",
            "CapInh: nope\nCapPrm: 0\nCapEff: 0\nCapBnd: 0\nCapAmb: 0\n",
            "CapInh: 0 trailing\nCapPrm: 0\nCapEff: 0\nCapBnd: 0\nCapAmb: 0\n",
            "CapInh: 0\nCapInh: 0\nCapPrm: 0\nCapEff: 0\nCapBnd: 0\nCapAmb: 0\n",
        ];

        for status in invalid {
            let error = CapabilityStatus::parse_proc_status(status).expect_err("invalid status");
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
    }

    #[test]
    fn nr_open_parser_is_pure_and_strict() {
        assert_eq!(parse_nr_open("1048576\n").expect("valid limit"), 1_048_576);
        assert!(parse_nr_open("not-a-number").is_err());
    }
}
