// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-to-guest TCP data that has been read from the host socket but not yet
//! acknowledged by the guest.
//!
//! Platforms without a socket peek offset (Windows, macOS) must consume data
//! from the socket before sending it to the guest, yet keep it until the guest
//! acknowledges it in case it must be retransmitted. This ring holds exactly
//! that data and is filled only up to the guest's advertised window, so the
//! host socket's receive buffer, not this ring, continues to provide
//! backpressure to the remote peer.

use thiserror::Error;

/// Smallest allocation once the ring holds any data.
const MIN_CAPACITY: usize = 4096;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("acknowledged {acked} bytes but only {sent} were sent")]
pub(crate) struct AckBeyondSent {
    pub acked: usize,
    pub sent: usize,
}

pub(crate) struct UnackedRing {
    buf: Box<[u8]>,
    /// Index of the oldest unacknowledged byte.
    head: usize,
    /// Bytes held, both sent and not yet sent.
    len: usize,
    /// Bytes at the start of the ring already sent to the guest.
    sent: usize,
    /// Capacity ceiling.
    max: usize,
}

impl UnackedRing {
    /// Creates an empty ring that allocates lazily up to `max` bytes.
    pub fn new(max: usize) -> Self {
        Self {
            buf: Box::default(),
            head: 0,
            len: 0,
            sent: 0,
            max,
        }
    }

    pub fn unsent(&self) -> usize {
        self.len - self.sent
    }

    /// Returns how many more bytes may be read from the host socket given the
    /// guest's current window, measured from the oldest unacknowledged byte.
    pub fn room(&self, guest_window: usize) -> usize {
        guest_window.min(self.max).saturating_sub(self.len)
    }

    /// Returns a contiguous region of at most `limit` bytes to read socket
    /// data into, growing the allocation if needed. Follow with
    /// [`Self::commit`]. The region may be shorter than `limit` when the free
    /// space wraps; call again after committing to fill the remainder.
    pub fn spare_mut(&mut self, limit: usize) -> &mut [u8] {
        let want = limit.min(self.max - self.len);
        if want == 0 {
            return &mut [];
        }
        if self.buf.len() - self.len < want {
            self.grow(self.len + want);
        }
        let cap = self.buf.len();
        let tail = (self.head + self.len) % cap;
        let n = (cap - tail).min(cap - self.len).min(want);
        &mut self.buf[tail..tail + n]
    }

    /// Records that `n` bytes were written to the region returned by
    /// [`Self::spare_mut`].
    pub fn commit(&mut self, n: usize) {
        assert!(n <= self.buf.len() - self.len);
        self.len += n;
    }

    /// Returns up to `max_len` bytes not yet sent to the guest, as two slices
    /// because the data may wrap.
    pub fn next_unsent(&self, max_len: usize) -> (&[u8], &[u8]) {
        let n = self.unsent().min(max_len);
        if n == 0 {
            return (&[], &[]);
        }
        let cap = self.buf.len();
        let start = (self.head + self.sent) % cap;
        let first = n.min(cap - start);
        (&self.buf[start..start + first], &self.buf[..n - first])
    }

    /// Records that `n` bytes returned by [`Self::next_unsent`] were sent.
    pub fn mark_sent(&mut self, n: usize) {
        assert!(n <= self.unsent());
        self.sent += n;
    }

    /// Releases `n` bytes acknowledged by the guest. The acknowledgment comes
    /// from the guest, so out-of-range values are rejected, not asserted.
    pub fn ack(&mut self, n: usize) -> Result<(), AckBeyondSent> {
        if n > self.sent {
            return Err(AckBeyondSent {
                acked: n,
                sent: self.sent,
            });
        }
        if n == 0 {
            return Ok(());
        }
        self.head = (self.head + n) % self.buf.len();
        self.len -= n;
        self.sent -= n;
        if self.len == 0 {
            self.head = 0;
        }
        Ok(())
    }

    /// Rewinds so that all unacknowledged data is sent again.
    pub fn rewind(&mut self) {
        self.sent = 0;
    }

    fn grow(&mut self, needed: usize) {
        assert!(needed <= self.max);
        let cap = needed.next_power_of_two().max(MIN_CAPACITY).min(self.max);
        let mut buf = vec![0; cap].into_boxed_slice();
        let (a, b) = self.held();
        buf[..a.len()].copy_from_slice(a);
        buf[a.len()..self.len].copy_from_slice(b);
        self.buf = buf;
        self.head = 0;
    }

    fn held(&self) -> (&[u8], &[u8]) {
        if self.len == 0 {
            return (&[], &[]);
        }
        let first = self.len.min(self.buf.len() - self.head);
        (
            &self.buf[self.head..self.head + first],
            &self.buf[..self.len - first],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    /// Simulates reading `data` from a socket into the ring.
    fn fill(ring: &mut UnackedRing, mut data: &[u8]) {
        while !data.is_empty() {
            let spare = ring.spare_mut(data.len());
            assert!(!spare.is_empty(), "ring full");
            let n = spare.len();
            spare.copy_from_slice(&data[..n]);
            ring.commit(n);
            data = &data[n..];
        }
    }

    fn take_unsent(ring: &mut UnackedRing, max_len: usize) -> Vec<u8> {
        let (a, b) = ring.next_unsent(max_len);
        let out = [a, b].concat();
        ring.mark_sent(out.len());
        out
    }

    #[test]
    fn room_is_bounded_by_guest_window_and_max() {
        let mut ring = UnackedRing::new(8192);
        assert_eq!(ring.room(1000), 1000);
        assert_eq!(ring.room(1 << 20), 8192);
        fill(&mut ring, &[0; 600]);
        // Held bytes count against the window whether or not they were sent.
        assert_eq!(ring.room(1000), 400);
        take_unsent(&mut ring, 600);
        assert_eq!(ring.room(1000), 400);
        // A guest shrinking its window below what is held yields no room.
        assert_eq!(ring.room(100), 0);
    }

    #[test]
    fn data_survives_wraparound_and_growth() {
        let mut ring = UnackedRing::new(MIN_CAPACITY * 4);
        let data: Vec<u8> = (0..MIN_CAPACITY * 3).map(|i| i as u8).collect();

        // Fill most of the minimum allocation, send and ack part, then fill
        // past the end so the data wraps.
        fill(&mut ring, &data[..3000]);
        assert_eq!(take_unsent(&mut ring, 2000), data[..2000]);
        ring.ack(2000).unwrap();
        fill(&mut ring, &data[3000..5000]);
        assert_eq!(take_unsent(&mut ring, usize::MAX), data[2000..5000]);

        // Growing while wrapped must preserve order.
        fill(&mut ring, &data[5000..]);
        assert_eq!(take_unsent(&mut ring, usize::MAX), data[5000..]);
        ring.ack(ring.len).unwrap();
        assert_eq!(ring.len, 0);
    }

    #[test]
    fn rewind_resends_from_oldest_unacked_byte() {
        let mut ring = UnackedRing::new(MIN_CAPACITY);
        let data: Vec<u8> = (0..100).collect();
        fill(&mut ring, &data);
        take_unsent(&mut ring, 60);
        ring.ack(20).unwrap();
        ring.rewind();
        assert_eq!(ring.unsent(), 80);
        assert_eq!(take_unsent(&mut ring, usize::MAX), data[20..]);
    }

    #[test]
    fn ack_beyond_sent_is_rejected_without_change() {
        let mut ring = UnackedRing::new(MIN_CAPACITY);
        fill(&mut ring, &[1; 50]);
        take_unsent(&mut ring, 10);
        assert_eq!(
            ring.ack(11),
            Err(AckBeyondSent {
                acked: 11,
                sent: 10
            })
        );
        assert_eq!((ring.len, ring.unsent()), (50, 40));
    }

    #[test]
    fn never_exceeds_max() {
        let mut ring = UnackedRing::new(MIN_CAPACITY + 100);
        fill(&mut ring, &vec![0; MIN_CAPACITY + 100]);
        assert!(ring.spare_mut(1).is_empty());
        assert_eq!(ring.buf.len(), MIN_CAPACITY + 100);
        take_unsent(&mut ring, usize::MAX);
        ring.ack(ring.len).unwrap();
        assert_eq!(ring.room(usize::MAX), MIN_CAPACITY + 100);
    }
}
