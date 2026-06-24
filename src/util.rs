use std::io;

use bytes::BytesMut;
use tokio::io::AsyncReadExt;

pub trait AsyncReadBufExt: AsyncReadExt + Unpin {
    async fn read_at_least(&mut self, buf: &mut BytesMut, expected: usize) -> io::Result<()> {
        while buf.len() < expected {
            let n = self.read_buf(buf).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        Ok(())
    }
}

impl<T: AsyncReadExt + Unpin + ?Sized> AsyncReadBufExt for T {}
