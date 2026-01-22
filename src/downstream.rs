use std::{
    fmt::Debug,
    future::poll_fn,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{Method, StatusCode};
use http::header::ALLOW;
use h2::server::SendResponse;
use iroh::{
    Endpoint, EndpointId,
    endpoint::{RecvStream, SendStream},
};
use iroh_blobs::util::connection_pool::{ConnectionPool, ConnectionRef};
use n0_error::{AnyError, Result, anyerr, stack_error};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error_span, warn};

pub use self::opts::{
    ExtractError, ForwardProxyMode, ForwardProxyResolver, HttpProxyOpts, PoolOpts, ProxyMode,
    ReverseProxyMode, ReverseProxyResolver, WriteErrorResponse,
};
use crate::{
    ALPN, Authority, HEADER_SECTION_MAX_LENGTH,
    parse::{HttpRequest, HttpProxyRequest, HttpResponse},
    util::{Prebuffered, forward_bidi},
};

pub(crate) mod opts;

/// Accepts TCP streams and forwards them to upstream iroh destinations.
#[derive(Clone, Debug)]
pub struct DownstreamProxy {
    pool: ConnectionPool,
}

impl DownstreamProxy {
    /// Creates a downstream proxy with the given endpoint and pool options.
    pub fn new(endpoint: Endpoint, opts: PoolOpts) -> Self {
        let pool = ConnectionPool::new(endpoint, ALPN, opts.into());
        Self { pool }
    }

    /// Opens a CONNECT tunnel to the upstream proxy and returns the client streams.
    ///
    /// Note: any non-`200 OK` response from upstream is returned as a `ProxyError`.
    pub async fn create_tunnel(
        &self,
        destination: &EndpointAuthority,
    ) -> Result<TunnelClientStreams, ProxyError> {
        let mut conn = self
            .connect(destination.endpoint_id)
            .await
            .map_err(ProxyError::gateway_timeout)?;
        conn.send
            .write_all(destination.authority.to_connect_request().as_bytes())
            .await?;
        let response = HttpResponse::read(&mut conn.recv)
            .await
            .map_err(ProxyError::bad_gateway)?;
        debug!(status=%response.status, "response from upstream");
        if response.status != StatusCode::OK {
            Err(ProxyError::new(
                Some(response.status),
                anyerr!("Upstream gateway returned error response"),
            ))
        } else {
            Ok(conn)
        }
    }

    /// Accepts TCP connections and serves HTTP/2 CONNECT requests.
    ///
    /// This expects h2c prior knowledge (direct HTTP/2 without an HTTP/1.1 upgrade).
    /// It enables multiplexing many CONNECT tunnels over a small pool of upstream TCP
    /// connections by using HTTP/2 streams.
    ///
    /// Requirements for H2 CONNECT clients:
    /// - Use CONNECT requests with a valid `:authority` (host:port) target.
    /// - Provide any headers needed by your `ForwardProxyResolver`
    /// - The proxy uses headers only to resolve the destination; they are not forwarded
    ///   across the Iroh hop.
    pub async fn forward_h2_listener(&self, listener: TcpListener, mode: ProxyMode) -> Result<()> {
        let cancel_token = CancellationToken::new();
        let _cancel_guard = cancel_token.clone().drop_guard();
        let mut id = 0;
        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            let this = self.clone();
            let mode = mode.clone();
            tokio::spawn(
                cancel_token
                    .child_token()
                    .run_until_cancelled_owned(async move {
                        debug!(%client_addr, "accepted HTTP/2 connection");
                        if let Err(err) = this.forward_h2_stream(client_stream, &mode).await {
                            warn!("Error while forwarding HTTP/2 stream: {err:#}");
                        }
                    })
                    .instrument(error_span!("h2-accept", id)),
            );
            id += 1;
        }
    }

    /// Accepts TCP connections from the listener and forwards each in a new task.
    ///
    /// Runs indefinitely until the listener errors or the task is cancelled.
    pub async fn forward_tcp_listener(&self, listener: TcpListener, mode: ProxyMode) -> Result<()> {
        let cancel_token = CancellationToken::new();
        let _cancel_guard = cancel_token.clone().drop_guard();
        let mut id = 0;
        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            let this = self.clone();
            let mode = mode.clone();
            tokio::spawn(
                cancel_token
                    .child_token()
                    .run_until_cancelled_owned(async move {
                        debug!(%client_addr, "accepted TCP connection");
                        this.forward_tcp_stream(client_stream, &mode).await.ok();
                    })
                    .instrument(error_span!("tcp-accept", id)),
            );
            id += 1;
        }
    }

    /// Serves a single HTTP/2 connection with CONNECT streams.
    async fn forward_h2_stream(&self, conn: TcpStream, mode: &ProxyMode) -> Result<()> {
        let mut connection =
            h2::server::handshake(conn).await.map_err(|err| anyerr!(err))?;
        while let Some(result) = connection.accept().await {
            let (request, respond) = result.map_err(|err| anyerr!(err))?;
            let this = self.clone();
            let mode = mode.clone();
            tokio::spawn(async move {
                if let Err(err) = this.handle_h2_request(request, respond, &mode).await {
                    warn!("Error while handling HTTP/2 request: {err:#}");
                }
            });
        }
        Ok(())
    }

    /// Forwards a single TCP stream.
    ///
    /// For [`ProxyMode::Http`], this parses the first HTTP request from the stream, and then forwards or rejects according
    /// to the configured [`HttpProxyOpts`].
    /// For [`ProxyMode::Tcp`], this creates a CONNECT tunnel to the configured upstream and authority, and forwards the TCP
    /// stream without parsing anything.
    pub async fn forward_tcp_stream(&self, mut conn: TcpStream, mode: &ProxyMode) -> Result<()> {
        if let Err(err) = self.forward_tcp_stream_inner(&mut conn, mode).await {
            warn!("Error while forwarding TCP stream: {err:#}");
            // If this is a HTTP proxy, write an error response if the error is a proxy error.
            if let ProxyMode::Http(opts) = mode
                && let Some(response) = err.to_response()
            {
                debug!(?response, "send error response");
                if let Err(err) = opts.write_error_response(&response, &mut conn).await {
                    debug!("failed to send error response: {err:#}");
                }
            }
            Err(err.into())
        } else {
            debug!("Forwarded stream closed");
            Ok(())
        }
    }

    async fn forward_tcp_stream_inner(
        &self,
        conn: &mut TcpStream,
        mode: &ProxyMode,
    ) -> Result<(), ProxyError> {
        let (tcp_recv, mut tcp_send) = conn.split();

        // We only need to prebuffer for HTTP mode.
        let prebuffer_max_len = match mode {
            ProxyMode::Tcp(_) => 0,
            ProxyMode::Http(_) => HEADER_SECTION_MAX_LENGTH,
        };
        let mut tcp_recv = Prebuffered::new(tcp_recv, prebuffer_max_len);

        let mut conn = match mode {
            ProxyMode::Tcp(destination) => self.create_tunnel(destination).await?,
            ProxyMode::Http(opts) => {
                // Read the HTTP header section, but don't remove it from the reader as it should be forwarded too.
                let (header_len, request) = HttpRequest::peek(&mut tcp_recv)
                    .await
                    .map_err(ProxyError::bad_request)?;
                debug!(?request, header_len, "read request");
                match &request {
                    HttpRequest::Forward(request) => {
                        let forward = opts.as_forward()?;
                        let destination = forward.destination(request).await?;
                        debug!(destination=%destination.fmt_short(), "forwarding proxy request");
                        self.connect(destination)
                            .await
                            .map_err(ProxyError::gateway_timeout)?
                    }
                    HttpRequest::Origin(request) => {
                        let reverse = opts.as_reverse()?;
                        let destination = reverse.destination(request).await?;
                        debug!(destination=%destination.fmt_short(), "forwarding origin request");
                        self.create_tunnel(&destination).await?
                    }
                }
            }
        };

        debug!(endpoint_id=%conn.conn.remote_id().fmt_short(), "tunnel established");
        forward_bidi(&mut tcp_recv, &mut tcp_send, &mut conn.recv, &mut conn.send)
            .await
            .map_err(ProxyError::io)?;
        Ok(())
    }

    /// Handles a single proxied tunnel given a resolved destination and IO stream.
    pub async fn serve_tunnel_io(
        &self,
        destination: &EndpointAuthority,
        io: impl AsyncRead + AsyncWrite + Unpin + Send,
    ) -> Result<(), ProxyError> {
        let conn = self.create_tunnel(destination).await?;
        self.forward_tunnel_io(conn, io).await
    }

    async fn connect(&self, destination: EndpointId) -> Result<TunnelClientStreams, ProxyError> {
        let conn = self
            .pool
            .get_or_connect(destination)
            .await
            .map_err(|err| ProxyError::gateway_timeout(anyerr!(err)))?;
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))?;
        let recv = Prebuffered::new(recv, HEADER_SECTION_MAX_LENGTH);
        Ok(TunnelClientStreams { send, recv, conn })
    }

    async fn forward_tunnel_io(
        &self,
        mut conn: TunnelClientStreams,
        io: impl AsyncRead + AsyncWrite + Unpin + Send,
    ) -> Result<(), ProxyError> {
        let (mut downstream_recv, mut downstream_send) = tokio::io::split(io);
        forward_bidi(
            &mut downstream_recv,
            &mut downstream_send,
            &mut conn.recv,
            &mut conn.send,
        )
        .await
        .map_err(ProxyError::io)?;
        Ok(())
    }

    async fn resolve_h2_forward_destination(
        &self,
        opts: &HttpProxyOpts,
        parts: &http::request::Parts,
    ) -> Result<EndpointAuthority, ProxyError> {
        let authority = authority_from_h2_parts(parts)?;
        let proxy_request = HttpProxyRequest {
            kind: crate::HttpProxyRequestKind::Tunnel { target: authority.clone() },
            headers: parts.headers.clone(),
        };
        let forward = opts.as_forward()?;
        let endpoint_id = forward.destination(&proxy_request).await?;
        Ok(EndpointAuthority::new(endpoint_id, authority))
    }

    async fn handle_h2_request(
        &self,
        request: http::Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        mode: &ProxyMode,
    ) -> Result<(), ProxyError> {
        let (parts, recv_stream) = request.into_parts();
        if parts.method != Method::CONNECT {
            send_h2_method_not_allowed(respond)?;
            return Err(ProxyError::method_not_allowed(anyerr!(
                "Expected CONNECT method"
            )));
        }

        let destination = match mode {
            ProxyMode::Tcp(destination) => destination.clone(),
            ProxyMode::Http(opts) => match self.resolve_h2_forward_destination(opts, &parts).await {
                Ok(destination) => destination,
                Err(err) => {
                    let status = err
                        .response_status()
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    send_h2_error_response(respond, status)?;
                    return Err(err);
                }
            },
        };

        let conn = match self.create_tunnel(&destination).await {
            Ok(conn) => conn,
            Err(err) => {
                let status = err
                    .response_status()
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                send_h2_error_response(respond, status)?;
                return Err(err);
            }
        };
        let response = http::Response::builder()
            .status(StatusCode::OK)
            .body(())
            .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))?;
        let send_stream = respond
            .send_response(response, false)
            .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))?;
        self.forward_h2_tunnel(conn, recv_stream, send_stream)
            .await?;
        Ok(())
    }

    async fn forward_h2_tunnel(
        &self,
        mut conn: TunnelClientStreams,
        recv_stream: h2::RecvStream,
        mut send_stream: h2::SendStream<Bytes>,
    ) -> Result<(), ProxyError> {
        let mut downstream_recv = H2RecvStream::new(recv_stream);
        let (down_to_up, up_to_down) = tokio::join!(
            async { tokio::io::copy(&mut downstream_recv, &mut conn.send).await },
            async {
                let res = copy_upstream_to_h2(&mut conn.recv, &mut send_stream).await;
                let _ = send_stream.send_data(Bytes::new(), true);
                res
            }
        );
        let down_to_up = down_to_up.map_err(ProxyError::io)?;
        let up_to_down = up_to_down.map_err(ProxyError::io)?;
        // NOTE: We intentionally do not call conn.send.finish() here.
        // The QUIC bidi stream represents a full-duplex tunnel; finishing the send side
        // can truncate upstream->downstream bytes depending on peer semantics.
        tracing::trace!(down_to_up, up_to_down, "forward h2 tunnel finished");
        Ok(())
    }
}

/// Bidirectional streams for a single iroh tunnel.
pub struct TunnelClientStreams {
    /// QUIC send stream toward the upstream proxy.
    pub send: SendStream,
    /// QUIC recv stream from the upstream proxy.
    pub recv: Prebuffered<RecvStream>,
    /// Connection handle kept alive for the tunnel lifetime.
    pub conn: ConnectionRef,
}

fn authority_from_h2_parts(parts: &http::request::Parts) -> Result<Authority, ProxyError> {
    if let Some(authority) = parts.uri.authority() {
        return Authority::from_authority_str(authority.as_str()).map_err(ProxyError::bad_request);
    }
    if let Some(host) = parts.headers.get(http::header::HOST) {
        let host = host
            .to_str()
            .map_err(|_| ProxyError::bad_request(anyerr!("Invalid Host header")))?;
        return Authority::from_authority_str(host).map_err(ProxyError::bad_request);
    }
    Err(ProxyError::bad_request(anyerr!(
        "Missing :authority for CONNECT request"
    )))
}

fn send_h2_error_response(
    mut respond: SendResponse<Bytes>,
    status: StatusCode,
) -> Result<(), ProxyError> {
    let response = http::Response::builder()
        .status(status)
        .body(())
        .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))?;
    respond
        .send_response(response, true)
        .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))?;
    Ok(())
}

fn send_h2_method_not_allowed(mut respond: SendResponse<Bytes>) -> Result<(), ProxyError> {
    let response = http::Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(ALLOW, "CONNECT")
        .body(())
        .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))?;
    respond
        .send_response(response, true)
        .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))?;
    Ok(())
}

struct H2RecvStream {
    inner: h2::RecvStream,
    buffer: Bytes,
    finished: bool,
}

impl H2RecvStream {
    fn new(inner: h2::RecvStream) -> Self {
        Self {
            inner,
            buffer: Bytes::new(),
            finished: false,
        }
    }
}

impl AsyncRead for H2RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(Ok(()));
        }
        if this.buffer.is_empty() {
            match Pin::new(&mut this.inner).poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(bytes))) => {
                    this.buffer = bytes;
                }
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, err)));
                }
                Poll::Ready(None) => {
                    this.finished = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
        let available = std::cmp::min(buf.remaining(), this.buffer.len());
        if available > 0 {
            let chunk = this.buffer.split_to(available);
            buf.put_slice(&chunk);
            let _ = this.inner.flow_control().release_capacity(available);
        }
        Poll::Ready(Ok(()))
    }
}

async fn copy_upstream_to_h2(
    reader: &mut (impl AsyncRead + Unpin),
    send_stream: &mut h2::SendStream<Bytes>,
) -> io::Result<u64> {
    let mut buf = [0u8; 32768];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        total += read as u64;
        let mut offset = 0;
        while offset < read {
            let capacity = await_capacity(send_stream, read - offset).await?;
            if capacity == 0 {
                tracing::trace!("h2 send_stream closed while forwarding");
                return Ok(total);
            }
            let to_send = std::cmp::min(capacity, read - offset);
            let data = Bytes::copy_from_slice(&buf[offset..offset + to_send]);
            send_stream
                .send_data(data, false)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            offset += to_send;
        }
    }
    Ok(total)
}

async fn await_capacity(
    send_stream: &mut h2::SendStream<Bytes>,
    want: usize,
) -> io::Result<usize> {
    loop {
        if send_stream.capacity() < want {
            send_stream.reserve_capacity(want);
        }
        let capacity = poll_fn(|cx| send_stream.poll_capacity(cx)).await;
        match capacity {
            Some(Ok(0)) => continue,
            Some(Ok(capacity)) => return Ok(capacity),
            Some(Err(err)) => return Err(io::Error::new(io::ErrorKind::Other, err)),
            None => return Ok(0),
        }
    }
}

#[derive(Debug, Clone)]
/// Endpoint identifier paired with the target authority.
pub struct EndpointAuthority {
    /// Destination iroh endpoint identifier.
    pub endpoint_id: EndpointId,
    /// Target authority for the CONNECT request.
    pub authority: Authority,
}

impl EndpointAuthority {
    /// Constructs an `EndpointAuthority` from its components.
    pub fn new(endpoint_id: EndpointId, authority: Authority) -> Self {
        Self {
            endpoint_id,
            authority,
        }
    }

    pub fn fmt_short(&self) -> String {
        format!("{}->{}", self.endpoint_id.fmt_short(), self.authority)
    }
}

/// Error type for downstream proxy failures.
#[stack_error(add_meta, derive)]
pub struct ProxyError {
    response_status: Option<StatusCode>,
    #[error(source)]
    source: AnyError,
}

impl From<ExtractError> for ProxyError {
    #[track_caller]
    fn from(value: ExtractError) -> Self {
        ProxyError::new(Some(value.response_status()), value.into())
    }
}

impl From<io::Error> for ProxyError {
    fn from(value: io::Error) -> Self {
        Self::io(value)
    }
}

impl From<iroh::endpoint::WriteError> for ProxyError {
    fn from(value: iroh::endpoint::WriteError) -> Self {
        Self::io(anyerr!(value))
    }
}

impl ProxyError {
    /// Returns the HTTP status code to surface to the client, if any.
    pub fn response_status(&self) -> Option<StatusCode> {
        self.response_status
    }

    fn to_response(&self) -> Option<HttpResponse> {
        self.response_status().map(HttpResponse::new)
    }

    fn bad_request(source: impl Into<AnyError>) -> Self {
        Self::new(Some(StatusCode::BAD_REQUEST), source.into())
    }

    fn method_not_allowed(source: impl Into<AnyError>) -> Self {
        Self::new(Some(StatusCode::METHOD_NOT_ALLOWED), source.into())
    }

    fn gateway_timeout(source: impl Into<AnyError>) -> Self {
        Self::new(Some(StatusCode::GATEWAY_TIMEOUT), source.into())
    }

    fn bad_gateway(source: impl Into<AnyError>) -> Self {
        Self::new(Some(StatusCode::BAD_GATEWAY), source.into())
    }

    fn io(source: impl Into<AnyError>) -> Self {
        Self::new(None, source.into())
    }
}
