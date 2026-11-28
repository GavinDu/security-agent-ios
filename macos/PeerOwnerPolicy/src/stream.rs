//! Private single-request stream framing. No listener or authorization.
//! The future OS-authenticated owner must authenticate the connected peer
//! and enforce its own admission/concurrency limit before invoking this.
//! A successful read only returns an untrusted request, never a capability.

use crate::{UntrustedRequest, FRAME_LEN};
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const MAX_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    InvalidBudget,
    Deadline,
    Truncated,
    TrailingData,
    InvalidFrame,
    Io,
}

/// Consumes one owned stream, so no subsequent parser can accidentally
/// interpret trailing bytes as a second request. The sender must shut down
/// its write half after exactly FRAME_LEN bytes. The EOF check is part of
/// the same absolute deadline, not a new timeout. No frame-sized allocation
/// depends on remote input. Closing the stream on every return is intended:
/// this is a one-way request ingress, not an end-to-end RPC protocol.
/// A future authenticated response path requires a separate reviewed design.
pub fn read_single_request(mut stream: UnixStream, budget: Duration)
    -> Result<(UntrustedRequest, UnixStream), ReadError>
{
    if budget.is_zero() || budget > MAX_BUDGET {
        return Err(ReadError::InvalidBudget);
    }
    let deadline = Instant::now().checked_add(budget).ok_or(ReadError::InvalidBudget)?;
    let mut frame = [0u8; FRAME_LEN];
    let mut offset = 0;
    while offset < frame.len() {
        let count = read_before(&mut stream, &mut frame[offset..], deadline)?;
        if count == 0 {
            return Err(ReadError::Truncated);
        }
        offset += count;
    }
    let mut extra = [0u8; 1];
    if read_before(&mut stream, &mut extra, deadline)? != 0 {
        return Err(ReadError::TrailingData);
    }
    let request = UntrustedRequest::decode(&frame).map_err(|_| ReadError::InvalidFrame)?;
    Ok((request, stream))
}

fn read_before(stream: &mut UnixStream, output: &mut [u8], deadline: Instant)
    -> Result<usize, ReadError>
{
    loop {
        let left = deadline.checked_duration_since(Instant::now()).ok_or(ReadError::Deadline)?;
        if left.is_zero() {
            return Err(ReadError::Deadline);
        }
        stream.set_read_timeout(Some(left)).map_err(|_| ReadError::Io)?;
        match stream.read(output) {
            Ok(count) => {
                if Instant::now() >= deadline {
                    return Err(ReadError::Deadline);
                }
                return Ok(count);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) =>
                return Err(ReadError::Deadline),
            Err(_) => return Err(ReadError::Io),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::Shutdown;
    use std::thread;

    fn valid_frame() -> [u8; FRAME_LEN] {
        let mut bytes = [0; FRAME_LEN];
        bytes[..4].copy_from_slice(b"SAPO");
        bytes[4] = 1;
        bytes[5] = 1;
        bytes[8..24].fill(1);
        bytes[24..40].fill(2);
        bytes[40..56].fill(3);
        bytes[56..64].copy_from_slice(&7u64.to_be_bytes());
        bytes[64..96].fill(42);
        bytes[96..128].fill(9);
        bytes
    }

    #[test]
    fn fragmented_valid_frame_requires_eof() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let frame = valid_frame();
        for part in frame.chunks(11) {
            writer.write_all(part).unwrap();
        }
        writer.shutdown(Shutdown::Write).unwrap();
        let (request, mut response) = read_single_request(reader, Duration::from_secs(2)).unwrap();
        assert_eq!(request.request_id(), [1; 16]);
        assert_eq!(request.revision(), 7);
        response.write_all(b"ok").unwrap();
        let mut reply = [0; 2];
        writer.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"ok");
    }

    #[test]
    fn refuses_short_overlong_and_invalid_frame() {
        let frame = valid_frame();
        let mut overlong = frame.to_vec();
        overlong.push(0);
        let mut invalid = frame;
        invalid[4] = 2;
        for (payload, expected) in [
            (frame[..FRAME_LEN-1].to_vec(), ReadError::Truncated),
            (overlong, ReadError::TrailingData),
            (invalid.to_vec(), ReadError::InvalidFrame),
        ] {
            let (reader, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(&payload).unwrap();
            writer.shutdown(Shutdown::Write).unwrap();
            assert!(matches!(read_single_request(reader, Duration::from_secs(2)), Err(e) if e == expected));
        }
    }

    #[test]
    fn full_frame_without_eof_is_not_accepted() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&valid_frame()).unwrap();
        assert!(matches!(read_single_request(reader, Duration::from_millis(100)), Err(ReadError::Deadline)));
        drop(writer);
    }

    #[test]
    fn slow_fragments_cannot_restart_deadline() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let sending = thread::spawn(move || {
            for byte in valid_frame() {
                if writer.write_all(&[byte]).is_err() { break; }
                thread::sleep(Duration::from_millis(10));
            }
        });
        assert!(matches!(read_single_request(reader, Duration::from_millis(150)), Err(ReadError::Deadline)));
        sending.join().unwrap();
    }

    #[test]
    fn zero_or_unbounded_budget_rejected() {
        for budget in [Duration::ZERO, Duration::from_secs(6)] {
            let (reader, _writer) = UnixStream::pair().unwrap();
            assert!(matches!(read_single_request(reader, budget), Err(ReadError::InvalidBudget)));
        }
    }
}
