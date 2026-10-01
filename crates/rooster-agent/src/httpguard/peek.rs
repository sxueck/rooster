//! 带前置缓冲的流包装:443 单监听上「先窥探 ClientHello、再决定
//! rustls 终止还是原样透传」的关键。
//!
//! `PeekStream` 把读到的字节缓存在自身,上层逻辑(如
//! [`super::clienthello::try_parse`])对缓冲做纯内存解析;之后所有
//! `AsyncRead` 先消费缓冲,缓冲耗尽才落到内层流,因此 ClientHello
//! 字节不会被丢弃——终止模式交给 rustls 重放,透传模式写给上游。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub(crate) struct PeekStream<S> {
    inner: S,
    buf: Vec<u8>,
    pos: usize,
}

impl<S> PeekStream<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// 当前已缓冲、尚未消费的窥探内容。
    pub(crate) fn buffer(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    pub(crate) fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> PeekStream<S> {
    /// 从内层流再读一段追加到窥探缓冲;返回读取字节数(0 = EOF)。
    pub(crate) async fn fill(&mut self) -> io::Result<usize> {
        let mut tmp = [0u8; 8192];
        let n = self.inner.read(&mut tmp).await?;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read_buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.buf.len() {
            let remain = self.buf.len() - self.pos;
            let n = remain.min(read_buf.remaining());
            read_buf.put_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, read_buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeekStream<S> {
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

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
