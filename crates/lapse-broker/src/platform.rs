//! Finding out which program is connected to the pipe.
//!
//! This matters more than it looks. Any process running as the user can open
//! the pipe, so an approval prompt that says only "something wants your
//! production password" is not a decision anyone can make. Naming the binary is
//! what turns the prompt into a real control.
//!
//! It is not a security boundary. An attacker who already runs code as the user
//! can start a process from any path they like, or inject into one the user
//! trusts. This identifies honest callers, which is what the design claims.

#![allow(unsafe_code)]

use crate::grant::ClientId;

#[cfg(windows)]
mod imp {
    use std::os::windows::io::{AsRawHandle, RawHandle};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use crate::grant::ClientId;

    /// Windows caps paths at this length for the classic API.
    const MAX_PATH_CHARS: usize = 32_767;

    pub fn identify(pipe: &impl AsRawHandle) -> ClientId {
        let Some(pid) = client_process_id(pipe.as_raw_handle()) else {
            return ClientId::unknown(0);
        };

        ClientId {
            pid,
            executable: image_path(pid),
        }
    }

    fn client_process_id(handle: RawHandle) -> Option<u32> {
        let mut pid: u32 = 0;

        // SAFETY: `handle` comes from a live NamedPipeServer we hold a borrow
        // of, so it is a valid pipe handle for the duration of the call, and
        // `pid` is a valid writable u32.
        let ok = unsafe { GetNamedPipeClientProcessId(handle as HANDLE, &mut pid) };

        (ok != 0 && pid != 0).then_some(pid)
    }

    fn image_path(pid: u32) -> Option<String> {
        // SAFETY: OpenProcess with a query-only access right; the returned
        // handle is checked for null and closed on every path below.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return None;
        }

        let mut buffer = vec![0u16; MAX_PATH_CHARS];
        let mut size = buffer.len() as u32;

        // SAFETY: `process` is a valid handle opened above, and the buffer and
        // size are consistent with one another.
        let ok = unsafe {
            QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut size)
        };

        // SAFETY: `process` is a valid handle that has not been closed yet.
        unsafe { CloseHandle(process) };

        if ok == 0 {
            return None;
        }

        buffer.truncate(size as usize);
        Some(String::from_utf16_lossy(&buffer))
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::grant::ClientId;

    /// Other platforms are not supported yet.
    ///
    /// Returning an unidentified client is the safe failure: unidentified
    /// callers never match an existing grant, so every request prompts.
    pub fn identify<T>(_pipe: &T) -> ClientId {
        ClientId::unknown(0)
    }
}

/// Identifies the process on the other end of a connection.
///
/// Returns an unidentified client rather than an error when identification
/// fails, which fails closed: [`ClientId`] with no executable never matches a
/// stored grant, so the user is asked again.
pub fn identify_peer<T>(pipe: &T) -> ClientId
where
    T: PeerHandle,
{
    pipe.identify()
}

/// Implemented by connection types that can name their peer.
pub trait PeerHandle {
    fn identify(&self) -> ClientId;
}

#[cfg(windows)]
impl PeerHandle for tokio::net::windows::named_pipe::NamedPipeServer {
    fn identify(&self) -> ClientId {
        imp::identify(self)
    }
}

#[cfg(not(windows))]
impl<T> PeerHandle for T {
    fn identify(&self) -> ClientId {
        imp::identify(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unidentified_client_carries_no_executable() {
        let client = ClientId::unknown(0);
        assert!(client.executable.is_none());
    }
}
