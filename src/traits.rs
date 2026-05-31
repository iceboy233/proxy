use async_trait::async_trait;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
};

pub trait AsyncStream: AsyncRead + AsyncWrite {}

impl<T: AsyncRead + AsyncWrite> AsyncStream for T {}

pub trait AsyncRecvFrom {
    fn poll_recv_from(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>>;
}

impl<P: AsyncRecvFrom + Unpin> AsyncRecvFrom for &mut P {
    fn poll_recv_from(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        Pin::new(&**self).poll_recv_from(cx, buf)
    }
}

impl<P: AsyncRecvFrom + Unpin> AsyncRecvFrom for Box<P> {
    fn poll_recv_from(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        Pin::new(&**self).poll_recv_from(cx, buf)
    }
}

impl<P> AsyncRecvFrom for Pin<P>
where
    P: std::ops::DerefMut + Unpin,
    P::Target: AsyncRecvFrom,
{
    fn poll_recv_from(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        self.get_ref().as_ref().poll_recv_from(cx, buf)
    }
}

// TODO: UdpDatagram
impl AsyncRecvFrom for UdpSocket {
    fn poll_recv_from(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        self.get_ref().poll_recv_from(cx, buf)
    }
}

pub trait AsyncRecvFromExt: AsyncRecvFrom {
    fn recv_from<'a, B: ?Sized>(&'a self, buf: &'a mut B) -> RecvFrom<'a, Self, B>
    where
        Self: Unpin,
    {
        RecvFrom {
            receiver: self,
            buf: buf,
        }
    }
}

impl<T: AsyncRecvFrom + ?Sized> AsyncRecvFromExt for T {}

#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct RecvFrom<'a, R: ?Sized, B: ?Sized> {
    receiver: &'a R,
    buf: &'a mut B,
}

impl<'a, 'b, R: AsyncRecvFrom + Unpin + ?Sized> Future for RecvFrom<'a, R, ReadBuf<'b>> {
    type Output = io::Result<SocketAddr>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.get_mut();
        Pin::new(me.receiver).poll_recv_from(cx, me.buf)
    }
}

pub trait AsyncSendTo {
    fn poll_send_to(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>>;
}

impl<P: AsyncSendTo + Unpin> AsyncSendTo for &mut P {
    fn poll_send_to(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        Pin::new(&**self).poll_send_to(cx, buf, target)
    }
}

impl<P: AsyncSendTo + Unpin> AsyncSendTo for Box<P> {
    fn poll_send_to(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        Pin::new(&**self).poll_send_to(cx, buf, target)
    }
}

impl<P> AsyncSendTo for Pin<P>
where
    P: std::ops::DerefMut + Unpin,
    P::Target: AsyncSendTo,
{
    fn poll_send_to(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.get_ref().as_ref().poll_send_to(cx, buf, target)
    }
}

// TODO: UdpDatagram
impl AsyncSendTo for UdpSocket {
    fn poll_send_to(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.get_ref().poll_send_to(cx, buf, target)
    }
}

pub trait AsyncSendToExt: AsyncSendTo {
    fn send_to<'a, B: ?Sized>(&'a self, buf: &'a B, target: SocketAddr) -> SendTo<'a, Self, B>
    where
        Self: Unpin,
    {
        SendTo {
            sender: self,
            buf: buf,
            target,
        }
    }
}

impl<T: AsyncSendTo + ?Sized> AsyncSendToExt for T {}

#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct SendTo<'a, S: ?Sized, B: ?Sized> {
    sender: &'a S,
    buf: &'a B,
    target: SocketAddr,
}

impl<'a, S: AsyncSendTo + Unpin + ?Sized> Future for SendTo<'a, S, [u8]> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.get_mut();
        Pin::new(me.sender).poll_send_to(cx, me.buf, me.target)
    }
}

pub trait AsyncDatagram: AsyncRecvFrom + AsyncSendTo {}

impl<T: AsyncRecvFrom + AsyncSendTo> AsyncDatagram for T {}

#[async_trait]
pub trait StreamConnector {
    async fn connect(
        &self,
        endpoint: SocketAddr,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>>;

    async fn connect_host(
        &self,
        host: &str,
        port: u16,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>>;
}

#[async_trait]
pub trait DatagramConnector {
    async fn bind(
        &self,
        endpoint: SocketAddr,
    ) -> io::Result<Box<dyn AsyncDatagram + Send + Sync + Unpin>>;
}

pub trait Connector: StreamConnector + DatagramConnector {}

impl<T: StreamConnector + DatagramConnector> Connector for T {}

#[async_trait]
pub trait StreamHandler {
    async fn handle_stream(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
    ) -> io::Result<()>;
}

#[async_trait]
pub trait DatagramHandler {
    async fn handle_datagram(
        &self,
        datagram: &(dyn AsyncDatagram + Send + Sync + Unpin),
    ) -> io::Result<()>;
}

pub trait Handler: StreamHandler + DatagramHandler {}

impl<T: StreamHandler + DatagramHandler> Handler for T {}
