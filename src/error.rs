use iroh::EndpointId;
use iroh::endpoint::{ConnectError, ConnectionError};
use n0_error::stack_error;
use std::io;

/// Errors that can occur when working with TCP proxy connections
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum TcpProxyError {
    /// Failed to bind TCP listener to the specified addresses
    #[error("failed to bind tcp socket to {addrs:?}")]
    TcpBind {
        /// The addresses we tried to bind to
        addrs: Vec<std::net::SocketAddr>,
        /// The underlying IO error
        #[error(source, std_err)]
        source: io::Error,
    },

    /// Failed to accept incoming TCP connection
    #[error("failed to accept tcp connection")]
    TcpAccept {
        #[error(source, std_err)]
        source: io::Error,
    },

    /// Failed to connect to remote endpoint
    #[error("failed to connect to endpoint {endpoint_id}")]
    EndpointConnect {
        /// The endpoint ID we tried to connect to
        endpoint_id: EndpointId,
        #[error(source, std_err)]
        source: ConnectError,
    },

    /// Failed to open bidirectional stream
    #[error("failed to open bidi stream to {endpoint_id}")]
    OpenBidi {
        /// The endpoint ID we tried to open a stream to
        endpoint_id: EndpointId,
        #[error(source, std_err)]
        source: ConnectionError,
    },

    /// Failed to accept incoming connection on endpoint
    #[error("failed to accept connection on endpoint")]
    EndpointAccept {
        #[error(source, std_err)]
        source: ConnectionError,
    },

    /// Failed to accept bidirectional stream
    #[error("failed to accept bidi stream")]
    AcceptBidi {
        #[error(source, std_err)]
        source: ConnectionError,
    },

    /// Failed to connect to TCP socket
    #[error("failed to connect to tcp socket {addrs:?}")]
    TcpConnect {
        /// The addresses we tried to connect to
        addrs: Vec<std::net::SocketAddr>,
        #[error(source, std_err)]
        source: io::Error,
    },

    /// IO error during operation
    #[error("io error")]
    Io {
        #[error(source, std_err)]
        source: io::Error,
    },

    /// Invalid handshake received
    #[error("invalid handshake received")]
    InvalidHandshake,
}

#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    TokenExpired,
    Forbidden,
}

#[derive(Debug)]
pub enum TunnelError {
    MissingDestination,
    InvalidNodeId,
    Auth(AuthError),
}
