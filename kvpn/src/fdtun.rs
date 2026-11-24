//! TUN ueber einen Datei-Deskriptor (Linux-Server, Linux-Client, Android-VpnService).

use crate::client::TunWriter;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

pub struct FdTun {
    fd: AsyncFd<OwnedFd>,
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl < 0 || libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

impl FdTun {
    /// uebernimmt den Deskriptor (wird beim Drop geschlossen). Muss innerhalb einer tokio-Laufzeit aufgerufen werden.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        set_nonblocking(fd.as_raw_fd())?;
        // SAFETY: OwnedFd bleibt bis zum Drop des AsyncFd offen und liefert immer denselben Deskriptor
        let fd = unsafe { AsyncFd::register(fd) }.map_err(|e| io::Error::other(e.to_string()))?;
        Ok(FdTun { fd })
    }

    /// # Safety
    /// `fd` muss ein gueltiger, offener Deskriptor sein, der niemand anderem gehoert.
    pub unsafe fn from_raw(fd: RawFd) -> io::Result<Self> {
        Self::new(OwnedFd::from_raw_fd(fd))
    }

    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut g = self.fd.readable().await?;
            match g.try_io(|inner| {
                let n = unsafe { libc::read(inner.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    pub fn write_now(&self, pkt: &[u8]) -> io::Result<usize> {
        let n = unsafe { libc::write(self.fd.as_raw_fd(), pkt.as_ptr() as *const libc::c_void, pkt.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl TunWriter for FdTun {
    fn write_packet(&self, pkt: &[u8]) {
        // nicht blockierend: ist die Warteschlange des Kernels voll, wird verworfen (wie ein Router)
        let _ = self.write_now(pkt);
    }
}

/// liest Pakete vom TUN und schiebt sie in den Kanal (Gegendruck: ist der Tunnel langsam, wartet das Lesen)
pub fn spawn_reader(tun: Arc<FdTun>, tx: mpsc::Sender<Vec<u8>>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match tun.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    })
}

/// Linux: TUN-Geraet oeffnen bzw. anlegen. `multi_queue`: mehrere Deskriptoren fuer dasselbe Geraet (ein Kern je Queue).
#[cfg(target_os = "linux")]
pub fn open_linux_tun(name: &str, multi_queue: bool) -> io::Result<OwnedFd> {
    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const IFF_MULTI_QUEUE: libc::c_short = 0x0100;
    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        flags: libc::c_short,
        _pad: [u8; 22],
    }
    if name.len() > 15 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Geraetename zu lang"));
    }
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = IfReq { name: [0; 16], flags: IFF_TUN | IFF_NO_PI | if multi_queue { IFF_MULTI_QUEUE } else { 0 }, _pad: [0; 22] };
    req.name[..name.len()].copy_from_slice(name.as_bytes());
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}
