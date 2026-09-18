//! Chunked transfer decoding.
//!
//! Bodies on a capability descriptor are capped and buffered, so this is a
//! whole-buffer decoder rather than a streaming one: it either finds a complete
//! chunked body, asks for more bytes, or rejects.

use crate::HttpError;

/// The result of attempting to decode a chunked body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkedOutcome {
    /// A complete body was decoded, consuming this many bytes of input.
    Complete {
        /// The decoded body.
        body: Vec<u8>,
        /// How many bytes of the input the body occupied.
        consumed: usize,
    },
    /// The input holds a well-formed prefix; more bytes are needed.
    NeedMore,
}

/// Decodes a chunked body from the front of `input`, refusing to accumulate
/// more than `limit` decoded bytes.
///
/// Chunk extensions and trailer fields are rejected rather than skipped. Both
/// are vanishingly rare, and a trailer is a way to smuggle header fields past
/// whatever inspected the head.
pub fn decode_chunked(input: &[u8], limit: u64) -> Result<ChunkedOutcome, HttpError> {
    let mut body: Vec<u8> = Vec::new();
    let mut pos = 0usize;

    loop {
        let line_end = match find_crlf(&input[pos..]) {
            Some(i) => pos + i,
            None => return Ok(ChunkedOutcome::NeedMore),
        };
        let size_line = &input[pos..line_end];

        // `a3;ext=1` — an extension. We do not interpret them, and skipping
        // something we have not interpreted is how a parser ends up disagreeing
        // with the next one along.
        if size_line.contains(&b';') {
            return Err(HttpError::BadChunk);
        }
        let size = parse_chunk_size(size_line)?;
        pos = line_end + 2;

        if size == 0 {
            // The trailer section must be empty: just the final CRLF.
            return match find_crlf(&input[pos..]) {
                None => Ok(ChunkedOutcome::NeedMore),
                Some(0) => Ok(ChunkedOutcome::Complete {
                    body,
                    consumed: pos + 2,
                }),
                Some(_) => Err(HttpError::BadChunk),
            };
        }

        if body.len() as u64 + size > limit {
            return Err(HttpError::BodyTooLarge);
        }

        let size = size as usize;
        if input.len() < pos + size + 2 {
            return Ok(ChunkedOutcome::NeedMore);
        }
        if &input[pos + size..pos + size + 2] != b"\r\n" {
            return Err(HttpError::BadChunk);
        }

        body.extend_from_slice(&input[pos..pos + size]);
        pos += size + 2;
    }
}

/// Parses a chunk size: hex digits only, nothing else.
fn parse_chunk_size(line: &[u8]) -> Result<u64, HttpError> {
    if line.is_empty() || line.len() > 16 || !line.iter().all(u8::is_ascii_hexdigit) {
        return Err(HttpError::BadChunk);
    }
    let text = std::str::from_utf8(line).map_err(|_| HttpError::BadChunk)?;
    u64::from_str_radix(text, 16).map_err(|_| HttpError::BadChunk)
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_complete_body() {
        let input = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(
            decode_chunked(input, 1024),
            Ok(ChunkedOutcome::Complete {
                body: b"Wikipedia".to_vec(),
                consumed: input.len(),
            })
        );
    }

    #[test]
    fn decodes_empty_body() {
        assert_eq!(
            decode_chunked(b"0\r\n\r\n", 1024),
            Ok(ChunkedOutcome::Complete {
                body: Vec::new(),
                consumed: 5
            })
        );
    }

    #[test]
    fn needs_more_on_truncation() {
        for prefix in ["4\r\nWi", "4\r\nWiki\r\n", "4\r\nWiki\r\n0\r\n", "4\r\n"] {
            assert_eq!(
                decode_chunked(prefix.as_bytes(), 1024),
                Ok(ChunkedOutcome::NeedMore),
                "{prefix:?}"
            );
        }
    }

    #[test]
    fn rejects_extensions_and_trailers() {
        assert_eq!(
            decode_chunked(b"4;x=1\r\nWiki\r\n0\r\n\r\n", 1024),
            Err(HttpError::BadChunk)
        );
        assert_eq!(
            decode_chunked(b"0\r\nX-Smuggled: 1\r\n\r\n", 1024),
            Err(HttpError::BadChunk)
        );
    }

    #[test]
    fn rejects_malformed_chunks() {
        assert_eq!(
            decode_chunked(b"zz\r\nWiki\r\n0\r\n\r\n", 1024),
            Err(HttpError::BadChunk)
        );
        assert_eq!(
            decode_chunked(b"-1\r\n\r\n", 1024),
            Err(HttpError::BadChunk)
        );
        // Chunk data not followed by CRLF.
        assert_eq!(
            decode_chunked(b"4\r\nWikiX\r\n0\r\n\r\n", 1024),
            Err(HttpError::BadChunk)
        );
    }

    #[test]
    fn enforces_the_limit() {
        assert_eq!(
            decode_chunked(b"10\r\n0123456789abcdef\r\n0\r\n\r\n", 8),
            Err(HttpError::BodyTooLarge)
        );
    }
}
