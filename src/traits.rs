use async_trait::async_trait;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait Stream: AsyncRead + AsyncWrite + Send + Sync {}

impl<T: AsyncRead + AsyncWrite + Send + Sync> Stream for T {}

pub trait AsyncRecvFrom {
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>>;
}

impl<P> AsyncRecvFrom for Pin<P>
where
    P: std::ops::DerefMut + Unpin,
    P::Target: AsyncRecvFrom,
{
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.get_mut().as_mut().poll_recv_from(cx, buf)
    }
}

pub trait AsyncRecvFromExt: AsyncRecvFrom {
    fn recv_from<'a>(&'a mut self, buf: &'a mut [u8]) -> RecvFrom<'a, Self>
    where
        Self: Unpin,
    {
        RecvFrom { receiver: self, buf }
    }
}

impl<T: AsyncRecvFrom + ?Sized> AsyncRecvFromExt for T {}

#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct RecvFrom<'a, R: ?Sized> {
    receiver: &'a mut R,
    buf: &'a mut [u8],
}

impl<R: AsyncRecvFrom + Unpin + ?Sized> Future for RecvFrom<'_, R> {
    type Output = io::Result<(usize, SocketAddr)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        Pin::new(&mut *me.receiver).poll_recv_from(cx, me.buf)
    }
}

pub trait AsyncSendTo {
    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>>;
}

impl<P> AsyncSendTo for Pin<P>
where
    P: std::ops::DerefMut + Unpin,
    P::Target: AsyncSendTo,
{
    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.get_mut().as_mut().poll_send_to(cx, buf, target)
    }
}

pub trait AsyncSendToExt: AsyncSendTo {
    fn send_to<'a>(&'a mut self, buf: &'a [u8], target: SocketAddr) -> SendTo<'a, Self>
    where
        Self: Unpin,
    {
        SendTo {
            sender: self,
            buf,
            target,
        }
    }
}

impl<T: AsyncSendTo + ?Sized> AsyncSendToExt for T {}

#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct SendTo<'a, S: ?Sized> {
    sender: &'a mut S,
    buf: &'a [u8],
    target: SocketAddr,
}

impl<S: AsyncSendTo + Unpin + ?Sized> Future for SendTo<'_, S> {
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        Pin::new(&mut *me.sender).poll_send_to(cx, me.buf, me.target)
    }
}

pub trait Datagram: AsyncRecvFrom + AsyncSendTo + Send + Sync {}

impl<T: AsyncRecvFrom + AsyncSendTo + Send + Sync> Datagram for T {}

#[async_trait]
pub trait Connector: Send + Sync {
    async fn connect(
        &self,
        endpoint: SocketAddr,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn Stream>>;

    async fn bind(&self, endpoint: SocketAddr) -> io::Result<Box<dyn Datagram>>;
}

pub trait Handler: Send + Sync {
    fn handle_stream(&self, stream: Box<dyn Stream>);
    fn handle_datagram(&self, datagram: Box<dyn Datagram>);
}
