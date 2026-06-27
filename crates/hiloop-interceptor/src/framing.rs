//! Byte-stream line framing for stdio capture.
//!
//! [`LineFramer`] turns an arbitrarily chunked byte stream into the
//! newline-delimited records the stdio capture contract (TESTING.md B6)
//! promises, independent of any async machinery. Keeping it synchronous and
//! self-contained makes the framing rules unit-testable on their own and lets a
//! future stdio [`crate::seams::Source`] reuse the exact same logic the
//! supervisor uses today.

/// Splits a byte stream into newline-delimited records with bounded chunking.
///
/// Rules (TESTING.md B6):
/// - `\n` terminates a record; a single trailing `\r` before it is trimmed, so
///   both LF and CRLF delimit records.
/// - An empty line between two newlines is a real, empty record.
/// - A record that grows past `max_record_bytes` without a newline is emitted
///   in `max_record_bytes`-sized chunks so memory stays bounded.
/// - Bytes still buffered when the stream ends are emitted once as a final
///   partial record by [`LineFramer::flush`].
///
/// Bytes are preserved verbatim; this type never interprets character encoding.
#[derive(Debug)]
pub struct LineFramer {
    pending: Vec<u8>,
    max_record_bytes: usize,
}

impl LineFramer {
    /// Create a framer that chunks unterminated records at `max_record_bytes`.
    ///
    /// # Panics
    ///
    /// Panics if `max_record_bytes` is zero, which could never make progress.
    #[must_use]
    pub fn new(max_record_bytes: usize) -> Self {
        assert!(
            max_record_bytes > 0,
            "max_record_bytes must be greater than zero"
        );
        Self {
            pending: Vec::new(),
            max_record_bytes,
        }
    }

    /// Feed a chunk of bytes, returning every record completed so far in order.
    ///
    /// Anything not yet terminated stays buffered for the next [`push`](Self::push)
    /// or for [`flush`](Self::flush).
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.pending.extend_from_slice(bytes);

        let mut records = Vec::new();
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            let mut record = self.pending.drain(..=newline).collect::<Vec<_>>();
            trim_line_ending(&mut record);
            records.push(record);
        }
        while self.pending.len() > self.max_record_bytes {
            let chunk = self
                .pending
                .drain(..self.max_record_bytes)
                .collect::<Vec<_>>();
            records.push(chunk);
        }
        records
    }

    /// Take any buffered bytes as a final partial record at end of stream.
    ///
    /// Returns `None` when nothing is buffered, so a stream that ends exactly on
    /// a newline does not emit a trailing empty record.
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.pending.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.pending))
        }
    }
}

fn trim_line_ending(record: &mut Vec<u8>) {
    if record.last() == Some(&b'\n') {
        record.pop();
    }
    if record.last() == Some(&b'\r') {
        record.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lf_and_crlf_delimit_records_and_trim_endings() {
        let mut framer = LineFramer::new(64);

        let out = framer.push(b"lf\ncrlf\r\n");

        assert_eq!(out, vec![b"lf".to_vec(), b"crlf".to_vec()]);
        assert!(framer.flush().is_none());
    }

    #[test]
    fn empty_line_is_a_record() {
        let mut framer = LineFramer::new(64);

        let out = framer.push(b"a\n\nb\n");

        assert_eq!(out, vec![b"a".to_vec(), Vec::new(), b"b".to_vec()]);
        assert!(framer.flush().is_none());
    }

    #[test]
    fn trailing_partial_is_emitted_on_flush() {
        let mut framer = LineFramer::new(64);

        let out = framer.push(b"done\npartial");

        assert_eq!(out, vec![b"done".to_vec()]);
        assert_eq!(framer.flush(), Some(b"partial".to_vec()));
        assert!(framer.flush().is_none());
    }

    #[test]
    fn chunks_record_longer_than_limit() {
        let mut framer = LineFramer::new(4);

        let out = framer.push(b"aaaaaa");

        assert_eq!(out, vec![b"aaaa".to_vec()]);
        assert_eq!(framer.flush(), Some(b"aa".to_vec()));
    }

    #[test]
    fn record_exactly_at_limit_then_newline_is_one_record() {
        let mut framer = LineFramer::new(4);

        let out = framer.push(b"aaaa\n");

        assert_eq!(out, vec![b"aaaa".to_vec()]);
        assert!(framer.flush().is_none());
    }

    #[test]
    fn bytes_are_preserved_across_split_pushes() {
        let mut framer = LineFramer::new(64);

        assert!(framer.push(b"hel").is_empty());
        let out = framer.push(b"lo\nwor");

        assert_eq!(out, vec![b"hello".to_vec()]);
        assert_eq!(framer.flush(), Some(b"wor".to_vec()));
    }

    #[test]
    fn preserves_non_utf8_bytes() {
        let mut framer = LineFramer::new(64);

        let out = framer.push(&[0xff, 0x00, b'A', b'\n']);

        assert_eq!(out, vec![vec![0xff, 0x00, b'A']]);
    }

    #[test]
    #[should_panic(expected = "greater than zero")]
    fn zero_limit_panics() {
        let _ = LineFramer::new(0);
    }
}
