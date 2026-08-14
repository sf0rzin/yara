//! Putting a secret on the clipboard, and taking it off again.
//!
//! This exists because the webview's clipboard is not good enough for a
//! password, in two separate ways.
//!
//! The first is Clipboard History. Anything copied with `navigator.clipboard`
//! is picked up by Win+V and, if the user turned it on, synced to their other
//! machines through the Cloud Clipboard. Keeping it out of both needs the
//! `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory`
//! and `CanUploadToCloudClipboard` formats placed on the clipboard beside the
//! text, and there is no way to place a registered clipboard format from
//! JavaScript at all.
//!
//! The second is the clear. The frontend used to write the password, wait
//! twenty seconds, read the clipboard back, and overwrite it if it had not
//! changed — with every rejection discarded. `readText()` is permission-gated
//! in WebView2 and the app declares no clipboard-read capability, so that read
//! could fail forever while the interface went on promising a clear that never
//! happened. Here the whole sequence is one thing that either worked or did
//! not, and says which.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::Serialize;
use yara_core::SecretString;

/// How long a copied secret is allowed to sit on the clipboard.
///
/// The frontend used the same twenty seconds. Long enough to switch to a login
/// form and paste, short enough that a walked-away-from machine is not holding
/// a password for anything that asks.
pub const CLEAR_AFTER_SECONDS: u64 = 20;

/// What one copy did, in terms the interface may repeat to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Copied {
    /// Whether Windows was told to keep this out of Clipboard History and the
    /// Cloud Clipboard. When it is false the interface must not claim the copy
    /// is private to this machine, because it is not.
    pub excluded_from_history: bool,
    /// Seconds until the copy is wiped.
    pub clears_in: u64,
    /// Which copy this is. The clear that follows carries the same number, so
    /// an event about an old copy cannot be read as being about a newer one.
    pub token: u64,
}

/// What became of a copy when its time was up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "outcome", content = "detail")]
pub enum Cleared {
    /// Taken off the clipboard.
    Wiped,
    /// Something else was on the clipboard by then, so there was nothing of
    /// ours to remove — and emptying it would have taken the user's own copy.
    AlreadyGone,
    /// Windows refused. The secret is still on the clipboard, and saying so is
    /// the only honest thing to do with this.
    Failed(String),
}

/// The platform clipboard.
///
/// A trait so the part that decides *whether* to wipe can be tested. The Win32
/// implementation needs an interactive window station, which a test runner is
/// not guaranteed to have.
pub trait Board: Send + Sync {
    /// Writes text and asks Windows to keep it out of history. The bool is
    /// whether that second half took.
    fn write(&self, text: &str) -> Result<bool, String>;

    /// Empties the clipboard, but only if it still holds `expected`.
    ///
    /// The comparison belongs here rather than in the caller because both
    /// halves have to happen under one hold on the clipboard. Reading and then
    /// emptying as two operations leaves a gap in which the user copies
    /// something and this throws it away.
    ///
    /// `Ok(false)` means the clipboard had moved on and nothing was touched.
    fn empty_if(&self, expected: &SecretString) -> Result<bool, String>;
}

/// The clipboard, plus a memory of what this app last put on it.
pub struct SecretClipboard {
    board: Box<dyn Board>,
    /// What was copied last, kept so a clear can leave alone anything the user
    /// copied since. Zeroized when it is dropped, like every other copy of a
    /// secret in this program.
    ours: Mutex<Option<SecretString>>,
    /// Bumped on every copy, so the timer belonging to an earlier copy cannot
    /// wipe a later one out from under the user.
    token: AtomicU64,
}

impl std::fmt::Debug for SecretClipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretClipboard")
            .field("token", &self.token.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SecretClipboard {
    pub fn new(board: Box<dyn Board>) -> Self {
        Self {
            board,
            ours: Mutex::new(None),
            token: AtomicU64::new(0),
        }
    }

    /// The one the application uses.
    pub fn platform() -> Self {
        Self::new(Box::new(platform::PlatformBoard))
    }

    /// Copies `secret`, replacing whatever this app copied before.
    pub fn copy(&self, secret: SecretString) -> Result<Copied, String> {
        let excluded_from_history = self.board.write(secret.expose())?;

        // Recorded only after the write succeeded. Remembering a secret that
        // never reached the clipboard would make the next clear compare
        // against something that was never there.
        let token = self.token.fetch_add(1, Ordering::SeqCst) + 1;
        if let Ok(mut ours) = self.ours.lock() {
            *ours = Some(secret);
        }

        Ok(Copied {
            excluded_from_history,
            clears_in: CLEAR_AFTER_SECONDS,
            token,
        })
    }

    /// The timer firing: wipes only if `token` is still the newest copy.
    pub fn clear_copy(&self, token: u64) -> Cleared {
        if self.token.load(Ordering::SeqCst) != token {
            // A later copy replaced this one and owns the clipboard now,
            // together with a timer of its own.
            return Cleared::AlreadyGone;
        }
        self.wipe()
    }

    /// Lock or exit: wipes whatever this app last copied, however long ago.
    ///
    /// Not only on the timer. A vault that locks with a password still on the
    /// clipboard has not locked anything, and the same goes for a process that
    /// exits.
    pub fn clear_now(&self) -> Cleared {
        self.wipe()
    }

    fn wipe(&self) -> Cleared {
        let Ok(mut ours) = self.ours.lock() else {
            return Cleared::Failed("clipboard state is unavailable".into());
        };
        let Some(secret) = ours.as_ref() else {
            return Cleared::AlreadyGone;
        };

        match self.board.empty_if(secret) {
            Ok(true) => {
                // Forgotten as soon as it is off the clipboard. Holding the
                // plaintext longer than the clipboard does would defeat the
                // point of taking it off.
                *ours = None;
                Cleared::Wiped
            }
            // The user copied something else in the meantime. Emptying the
            // clipboard now would throw away their copy to remove one that is
            // no longer there.
            Ok(false) => {
                *ours = None;
                Cleared::AlreadyGone
            }
            // Kept on purpose. The secret is still on the clipboard, so the
            // next attempt — the lock, or the exit — has to have something to
            // compare against. Forgetting it here would turn one busy
            // clipboard into a password left there for good.
            Err(error) => Cleared::Failed(error),
        }
    }
}

#[cfg(windows)]
mod platform {
    //! The Win32 clipboard.

    use std::ptr;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{GlobalFree, HANDLE};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, RegisterClipboardFormatW,
        SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
    };
    use yara_core::SecretString;

    use super::Board;

    /// The clipboard's own name for UTF-16 text.
    ///
    /// Written out rather than imported from `Win32_System_Ole`, which is a
    /// large module to compile in for one number that has been 13 since 1990.
    const CF_UNICODETEXT: u32 = 13;

    /// Its presence, whatever the contents, tells every clipboard monitor —
    /// history, Cloud Clipboard, third-party managers — to skip this entry.
    const EXCLUDE_FROM_MONITORS: &str = "ExcludeClipboardContentFromMonitorProcessing";
    /// A DWORD 0 keeps it out of Win+V specifically.
    const NOT_IN_HISTORY: &str = "CanIncludeInClipboardHistory";
    /// A DWORD 0 keeps it off the user's other machines.
    const NOT_IN_CLOUD: &str = "CanUploadToCloudClipboard";

    /// How many times to retry opening the clipboard, and how long to wait.
    ///
    /// Only one process may hold the clipboard open at a time, and something
    /// else holding it for a few milliseconds is ordinary rather than an
    /// error. A hundred milliseconds of trying is invisible to a person and
    /// long enough to outlast another application's copy.
    const OPEN_ATTEMPTS: u32 = 10;
    const OPEN_RETRY: Duration = Duration::from_millis(10);

    /// An open clipboard, closed when it goes out of scope.
    ///
    /// A guard rather than paired calls because the clipboard is a machine-wide
    /// lock: an early return that skipped `CloseClipboard` would leave every
    /// other program on the desktop unable to copy anything until yara exited.
    struct Session;

    impl Session {
        fn open() -> Result<Self, String> {
            for attempt in 0..OPEN_ATTEMPTS {
                // SAFETY: a null owner window is documented as associating the
                // clipboard with the current task. Zero means it did not open.
                if unsafe { OpenClipboard(ptr::null_mut()) } != 0 {
                    return Ok(Self);
                }
                if attempt + 1 < OPEN_ATTEMPTS {
                    std::thread::sleep(OPEN_RETRY);
                }
            }

            // The OS error comes along because the two reasons this fails are
            // not the same problem and the interface should not have to guess
            // between them: another program holding the clipboard is a retry,
            // and a session with no window station — a service, a headless
            // test runner — is never going to work at all.
            Err(format!(
                "the clipboard could not be opened ({})",
                std::io::Error::last_os_error()
            ))
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            // SAFETY: this session opened the clipboard, so this is the
            // matching close.
            unsafe { CloseClipboard() };
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Copies `units` into moveable global memory, as `SetClipboardData` wants.
    ///
    /// Ownership passes to the system on a successful `SetClipboardData` and
    /// not before, so the caller must free the block if the clipboard refuses
    /// it.
    fn allocate(units: &[u16]) -> Option<HANDLE> {
        let bytes = std::mem::size_of_val(units);

        // SAFETY: `GlobalAlloc` returns null on failure, which is checked
        // before the handle is used.
        let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) };
        if handle.is_null() {
            return None;
        }

        // SAFETY: the handle came from `GlobalAlloc` above and the block is
        // `bytes` long, which is exactly how much is written into it.
        unsafe {
            let target = GlobalLock(handle) as *mut u16;
            if target.is_null() {
                GlobalFree(handle);
                return None;
            }
            ptr::copy_nonoverlapping(units.as_ptr(), target, units.len());
            GlobalUnlock(handle);
        }

        Some(handle)
    }

    /// Puts `units` on the open clipboard under `id`.
    fn place(id: u32, units: &[u16]) -> bool {
        let Some(handle) = allocate(units) else {
            return false;
        };

        // SAFETY: the clipboard is open and owned by this task, and `handle`
        // is the kind of global memory block `SetClipboardData` expects.
        let placed = unsafe { !SetClipboardData(id, handle).is_null() };
        if !placed {
            // SAFETY: the clipboard refused it, so this side still owns it.
            unsafe { GlobalFree(handle) };
        }
        placed
    }

    /// Registers a clipboard format by name, or 0 if Windows would not.
    fn register(name: &str) -> u32 {
        let name = wide(name);
        // SAFETY: `wide` always produces a NUL-terminated buffer, which is
        // what a `PCWSTR` is, and it outlives the call.
        unsafe { RegisterClipboardFormatW(name.as_ptr()) }
    }

    /// A DWORD zero: "no, do not".
    const REFUSE: [u16; 2] = [0, 0];

    /// Reads the clipboard's text. The clipboard must already be open.
    fn text() -> Option<SecretString> {
        // SAFETY: the caller holds the clipboard open. A null return means
        // there is no text on it, which is checked.
        let handle = unsafe { GetClipboardData(CF_UNICODETEXT) };
        if handle.is_null() {
            return None;
        }

        // SAFETY: the handle belongs to the clipboard and stays valid while it
        // is held open. The length comes from `GlobalSize` rather than from
        // trusting a terminator to be there — with `panic = "abort"` a walk
        // off the end of the block is a crash dump with a password in it.
        unsafe {
            let start = GlobalLock(handle) as *const u16;
            if start.is_null() {
                return None;
            }

            let capacity = GlobalSize(handle) / std::mem::size_of::<u16>();
            let units = std::slice::from_raw_parts(start, capacity);
            let len = units.iter().position(|unit| *unit == 0).unwrap_or(capacity);
            let value = String::from_utf16_lossy(&units[..len]);

            GlobalUnlock(handle);
            Some(SecretString::new(value))
        }
    }

    pub struct PlatformBoard;

    impl Board for PlatformBoard {
        fn write(&self, secret: &str) -> Result<bool, String> {
            let _session = Session::open()?;

            // SAFETY: the clipboard is open. Emptying it is what makes this
            // task the owner, which every `SetClipboardData` below requires.
            if unsafe { EmptyClipboard() } == 0 {
                return Err("the clipboard could not be cleared for writing".into());
            }

            if !place(CF_UNICODETEXT, &wide(secret)) {
                return Err("the clipboard refused the text".into());
            }

            // All three or none, as far as the caller is concerned. A partial
            // exclusion reported as success would let the interface say "not
            // saved to history" when one of the three monitors was never told.
            let excluded = [EXCLUDE_FROM_MONITORS, NOT_IN_HISTORY, NOT_IN_CLOUD]
                .into_iter()
                .all(|name| match register(name) {
                    0 => false,
                    id => place(id, &REFUSE),
                });

            Ok(excluded)
        }

        fn empty_if(&self, expected: &SecretString) -> Result<bool, String> {
            let _session = Session::open()?;

            // Constant-time, courtesy of `SecretString`, and under the same
            // hold on the clipboard as the empty below.
            if text().as_ref() != Some(expected) {
                return Ok(false);
            }

            // SAFETY: the clipboard is open.
            if unsafe { EmptyClipboard() } == 0 {
                return Err("the clipboard could not be cleared".into());
            }
            Ok(true)
        }
    }
}

#[cfg(not(windows))]
mod platform {
    //! There is no clipboard here.
    //!
    //! The app is Windows-only; this exists so the crate still type-checks
    //! elsewhere rather than to be used.

    use yara_core::SecretString;

    use super::Board;

    pub struct PlatformBoard;

    impl Board for PlatformBoard {
        fn write(&self, _secret: &str) -> Result<bool, String> {
            Err("this platform has no clipboard".into())
        }

        fn empty_if(&self, _expected: &SecretString) -> Result<bool, String> {
            Err("this platform has no clipboard".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// A clipboard in a variable, so the decisions above can be tested without
    /// a window station.
    #[derive(Default)]
    struct Fake {
        contents: Mutex<Option<String>>,
        excluded: bool,
        refuse_write: bool,
        refuse_empty: std::sync::atomic::AtomicBool,
    }

    impl Fake {
        fn excluding() -> Self {
            Self {
                excluded: true,
                ..Self::default()
            }
        }

        fn holding(&self, text: &str) {
            *self.contents.lock().unwrap() = Some(text.to_string());
        }

        fn contents(&self) -> Option<String> {
            self.contents.lock().unwrap().clone()
        }
    }

    /// Shared, so a test can still look at the clipboard it handed over.
    #[derive(Clone)]
    struct Shared(Arc<Fake>);

    impl Board for Shared {
        fn write(&self, secret: &str) -> Result<bool, String> {
            if self.0.refuse_write {
                return Err("no".into());
            }
            self.0.holding(secret);
            Ok(self.0.excluded)
        }

        fn empty_if(&self, expected: &SecretString) -> Result<bool, String> {
            if self.0.refuse_empty.load(Ordering::SeqCst) {
                return Err("no".into());
            }
            let mut contents = self.0.contents.lock().unwrap();
            if contents.as_deref() != Some(expected.expose()) {
                return Ok(false);
            }
            *contents = None;
            Ok(true)
        }
    }

    fn clipboard(fake: Fake) -> (Arc<Fake>, SecretClipboard) {
        let shared = Arc::new(fake);
        let board = Shared(Arc::clone(&shared));
        (shared, SecretClipboard::new(Box::new(board)))
    }

    #[test]
    fn a_copy_is_wiped_when_its_time_is_up() {
        let (fake, clipboard) = clipboard(Fake::excluding());

        let copied = clipboard.copy(SecretString::new("hunter2")).unwrap();
        assert_eq!(fake.contents().as_deref(), Some("hunter2"));

        assert_eq!(clipboard.clear_copy(copied.token), Cleared::Wiped);
        assert_eq!(fake.contents(), None);
    }

    #[test]
    fn the_interface_is_told_whether_the_exclusion_took() {
        let (_, excluding) = clipboard(Fake::excluding());
        assert!(
            excluding
                .copy(SecretString::new("hunter2"))
                .unwrap()
                .excluded_from_history
        );

        // A clipboard that would not take the formats has to say so rather
        // than let the interface promise Win+V will not show the password.
        let (_, plain) = clipboard(Fake::default());
        assert!(
            !plain
                .copy(SecretString::new("hunter2"))
                .unwrap()
                .excluded_from_history
        );
    }

    #[test]
    fn something_the_user_copied_since_is_left_alone() {
        let (fake, clipboard) = clipboard(Fake::excluding());
        let copied = clipboard.copy(SecretString::new("hunter2")).unwrap();

        fake.holding("a shopping list");

        assert_eq!(clipboard.clear_copy(copied.token), Cleared::AlreadyGone);
        assert_eq!(fake.contents().as_deref(), Some("a shopping list"));
    }

    #[test]
    fn an_earlier_timer_does_not_wipe_a_later_copy() {
        // Copy, copy again inside the window, and let the first timer fire.
        // Without the token it would empty the clipboard twenty seconds into a
        // copy the user made two seconds ago.
        let (fake, clipboard) = clipboard(Fake::excluding());
        let first = clipboard.copy(SecretString::new("hunter2")).unwrap();
        let second = clipboard.copy(SecretString::new("correct horse")).unwrap();

        assert_eq!(clipboard.clear_copy(first.token), Cleared::AlreadyGone);
        assert_eq!(fake.contents().as_deref(), Some("correct horse"));

        assert_eq!(clipboard.clear_copy(second.token), Cleared::Wiped);
        assert_eq!(fake.contents(), None);
    }

    #[test]
    fn locking_wipes_a_copy_the_timer_has_not_reached() {
        // A vault that locks with a password still on the clipboard has not
        // locked anything.
        let (fake, clipboard) = clipboard(Fake::excluding());
        clipboard.copy(SecretString::new("hunter2")).unwrap();

        assert_eq!(clipboard.clear_now(), Cleared::Wiped);
        assert_eq!(fake.contents(), None);
    }

    #[test]
    fn a_second_clear_takes_nothing_that_is_not_ours() {
        let (fake, clipboard) = clipboard(Fake::excluding());
        clipboard.copy(SecretString::new("hunter2")).unwrap();
        assert_eq!(clipboard.clear_now(), Cleared::Wiped);

        fake.holding("a shopping list");
        assert_eq!(clipboard.clear_now(), Cleared::AlreadyGone);
        assert_eq!(fake.contents().as_deref(), Some("a shopping list"));
    }

    #[test]
    fn a_refused_wipe_is_reported_rather_than_swallowed() {
        // The old frontend discarded this rejection, which is how the clear
        // could fail permanently while the interface kept promising it.
        let (fake, clipboard) = clipboard(Fake {
            refuse_empty: true.into(),
            excluded: true,
            ..Fake::default()
        });
        let copied = clipboard.copy(SecretString::new("hunter2")).unwrap();

        assert!(matches!(
            clipboard.clear_copy(copied.token),
            Cleared::Failed(_)
        ));
        assert_eq!(fake.contents().as_deref(), Some("hunter2"));
    }

    #[test]
    fn a_wipe_that_failed_is_tried_again_at_the_next_chance() {
        // Something else holding the clipboard for a moment must not turn into
        // a password left on it for good, so a failed clear keeps the copy on
        // record for the lock or the exit to retry.
        let (fake, clipboard) = clipboard(Fake {
            refuse_empty: true.into(),
            excluded: true,
            ..Fake::default()
        });
        let copied = clipboard.copy(SecretString::new("hunter2")).unwrap();
        assert!(matches!(
            clipboard.clear_copy(copied.token),
            Cleared::Failed(_)
        ));

        fake.refuse_empty.store(false, Ordering::SeqCst);
        assert_eq!(clipboard.clear_now(), Cleared::Wiped);
        assert_eq!(fake.contents(), None);
    }

    #[test]
    fn a_copy_that_never_landed_is_not_remembered_as_ours() {
        let (fake, clipboard) = clipboard(Fake {
            refuse_write: true,
            ..Fake::default()
        });
        fake.holding("a shopping list");

        assert!(clipboard.copy(SecretString::new("hunter2")).is_err());
        // Nothing of ours went on, so nothing comes off — least of all the
        // thing that was already there.
        assert_eq!(clipboard.clear_now(), Cleared::AlreadyGone);
        assert_eq!(fake.contents().as_deref(), Some("a shopping list"));
    }

    /// The Win32 half, which the tests above deliberately do not reach.
    ///
    /// Ignored because it needs an interactive window station: the clipboard
    /// belongs to one, and a test runner in a service session has none. Run it
    /// with `cargo test -p yara-desktop -- --ignored` while logged in.
    #[test]
    #[ignore = "needs an interactive window station"]
    fn the_real_clipboard_round_trips() {
        let clipboard = SecretClipboard::platform();
        let copied = clipboard.copy(SecretString::new("hunter2")).unwrap();
        assert!(copied.excluded_from_history);
        assert_eq!(clipboard.clear_copy(copied.token), Cleared::Wiped);
    }
}
