use crate::codec::ZmqCodec;

use asynchronous_codec::{FramedRead, FramedWrite};
use futures::{AsyncRead, AsyncWrite};
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

const MAX_INBOUND_PEERS: usize = 256;
static INBOUND_PEERS: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct InboundPermit {
    counter: &'static AtomicUsize,
}
impl InboundPermit {
    pub(crate) fn acquire() -> Option<Arc<Self>> {
        Self::acquire_from(&INBOUND_PEERS)
    }

    fn acquire_from(counter: &'static AtomicUsize) -> Option<Arc<Self>> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_INBOUND_PEERS).then_some(count + 1)
            })
            .ok()
            .map(|_| Arc::new(Self { counter }))
    }
}
impl Drop for InboundPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

struct PermitIo<T> {
    inner: T,
    _permit: Arc<InboundPermit>,
}
impl<T: AsyncRead + Unpin> AsyncRead for PermitIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for PermitIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

// Enables us to have multiple bounds on the dyn trait in `InnerFramed`
pub trait FrameableRead: AsyncRead + Unpin + Send + Sync {}
impl<T> FrameableRead for T where T: AsyncRead + Unpin + Send + Sync {}
pub trait FrameableWrite: AsyncWrite + Unpin + Send + Sync {}
impl<T> FrameableWrite for T where T: AsyncWrite + Unpin + Send + Sync {}

pub(crate) type ZmqFramedRead = asynchronous_codec::FramedRead<Box<dyn FrameableRead>, ZmqCodec>;
pub(crate) type ZmqFramedWrite = asynchronous_codec::FramedWrite<Box<dyn FrameableWrite>, ZmqCodec>;

/// Equivalent to [`asynchronous_codec::Framed<T, ZmqCodec>`]
pub struct FramedIo {
    pub read_half: ZmqFramedRead,
    pub write_half: ZmqFramedWrite,
}

impl FramedIo {
    pub fn new(read_half: Box<dyn FrameableRead>, write_half: Box<dyn FrameableWrite>) -> Self {
        let read_half = FramedRead::new(read_half, ZmqCodec::new());
        let write_half = FramedWrite::new(write_half, ZmqCodec::new());
        Self {
            read_half,
            write_half,
        }
    }

    // Called immediately after accept, before either codec has been polled.
    pub(crate) fn with_inbound_permit(self, permit: Arc<InboundPermit>) -> Self {
        Self::new(
            Box::new(PermitIo {
                inner: self.read_half.into_inner(),
                _permit: permit.clone(),
            }),
            Box::new(PermitIo {
                inner: self.write_half.into_inner(),
                _permit: permit,
            }),
        )
    }

    pub fn into_parts(self) -> (ZmqFramedRead, ZmqFramedWrite) {
        (self.read_half, self.write_half)
    }
}

#[cfg(test)]
#[path = "framed_limits_test.rs"]
mod limits_test;
