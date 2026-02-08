use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use libp2p::request_response::Codec;
use std::io;

use crate::messaging::MessageEnvelope;

#[derive(Debug, Clone)]
pub struct ChatProtocol();

#[derive(Clone, Default)]
pub struct ChatCodec();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatRequest(pub MessageEnvelope);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatResponse(pub Vec<u8>);

impl AsRef<str> for ChatProtocol {
    fn as_ref(&self) -> &str {
        "/securechat/chat/1.0.0"
    }
}

#[async_trait]
impl Codec for ChatCodec {
    type Protocol = ChatProtocol;
    type Request = ChatRequest;
    type Response = ChatResponse;

    async fn read_request<T>(
        &mut self,
        _: &ChatProtocol,
        io: &mut T,
    ) -> io::Result<ChatRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        // ... implementation (keep same)
        let len = read_length(io).await?;
        if len > 10 * 1024 * 1024 { // 10MB limit
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large"));
        }

        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;

        let envelope = MessageEnvelope::from_bytes(&buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid envelope"))?;

        Ok(ChatRequest(envelope))
    }

    async fn read_response<T>(
        &mut self,
        _: &ChatProtocol,
        io: &mut T,
    ) -> io::Result<ChatResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        let len = read_length(io).await?;
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(ChatResponse(buf))
    }

    async fn write_request<T>(
        &mut self,
        _: &ChatProtocol,
        io: &mut T,
        ChatRequest(envelope): ChatRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = envelope.to_bytes();
        write_length(io, bytes.len()).await?;
        io.write_all(&bytes).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &ChatProtocol,
        io: &mut T,
        ChatResponse(data): ChatResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length(io, data.len()).await?;
        io.write_all(&data).await?;
        Ok(())
    }
}

pub type ChatBehaviour = libp2p::request_response::Behaviour<ChatCodec>;
pub type ChatEvent = libp2p::request_response::Event<ChatRequest, ChatResponse>;

async fn read_length<T>(io: &mut T) -> io::Result<usize> 
where T: AsyncRead + Unpin + Send
{
    let mut buf = [0u8; 4];
    io.read_exact(&mut buf).await?;
    Ok(u32::from_be_bytes(buf) as usize)
}

async fn write_length<T>(io: &mut T, len: usize) -> io::Result<()>
where T: AsyncWrite + Unpin + Send
{
    let buf = (len as u32).to_be_bytes();
    io.write_all(&buf).await?;
    Ok(())
}
