use super::directions::{IncomingDataEvent, IncomingDirection, OutgoingDataEvent, OutgoingDirection};
use super::error::Error;
use super::proxy_handler::{ConnectionManager, ProxyHandler};
use super::session_info::{IpProtocol, SessionInfo};
use anyhow::bail;
use base64::Engine;
use httparse::Response;
use socks5_impl::protocol::UserKey;
use std::{
    collections::{hash_map::RandomState, HashMap, VecDeque},
    iter::FromIterator,
    net::SocketAddr,
    str,
    sync::Arc,
};
use tokio::sync::Mutex;
use unicase::UniCase;

#[derive(Eq, PartialEq, Debug)]
#[allow(dead_code)]
enum AuthenticationScheme {
    None,
    Basic,
    Digest,
}

#[derive(Eq, PartialEq, Debug)]
#[allow(dead_code)]
enum HttpState {
    SendRequest,
    ExpectResponseHeaders,
    ExpectResponse,
    Reset,
    Established,
}

pub type DigestState = digest_auth::WwwAuthenticateHeader;

#[derive(Debug)]
pub struct HttpConnection {
    state: HttpState,
    client_inbuf: VecDeque<u8>,
    server_inbuf: VecDeque<u8>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    crlf_state: u8,
    counter: usize,
    skip: usize,
    digest_state: Arc<Mutex<Option<DigestState>>>,
    before: bool,
    credentials: Option<UserKey>,
    info: SessionInfo,
}

static PROXY_AUTHENTICATE: &str = "Proxy-Authenticate";
static PROXY_AUTHORIZATION: &str = "Proxy-Authorization";
static CONNECTION: &str = "Connection";
static TRANSFER_ENCODING: &str = "Transfer-Encoding";
static CONTENT_LENGTH: &str = "Content-Length";

impl HttpConnection {
    async fn new(info: SessionInfo, credentials: Option<UserKey>, digest_state: Arc<Mutex<Option<DigestState>>>) -> anyhow::Result<Self> {
        let mut res = Self {
            state: HttpState::ExpectResponseHeaders,
            client_inbuf: VecDeque::default(),
            server_inbuf: VecDeque::default(),
            client_outbuf: VecDeque::default(),
            server_outbuf: VecDeque::default(),
            skip: 0,
            counter: 0,
            crlf_state: 0,
            digest_state,
            before: false,
            credentials,
            info,
        };

        res.send_tunnel_request().await?;
        Ok(res)
    }

    async fn send_tunnel_request(&mut self) -> anyhow::Result<()> {
        self.server_outbuf.extend(b"CONNECT ");
        self.server_outbuf.extend(self.info.dst.to_string().as_bytes());
        self.server_outbuf.extend(b" HTTP/1.1\r\nHost: ");
        self.server_outbuf.extend(self.info.dst.to_string().as_bytes());
        self.server_outbuf.extend(b"\r\n");

        let scheme = if self.digest_state.lock().await.is_none() {
            AuthenticationScheme::Basic
        } else {
            AuthenticationScheme::Digest
        };
        self.send_auth_data(scheme).await?;

        self.server_outbuf.extend(b"\r\n");
        Ok(())
    }

    async fn send_auth_data(&mut self, scheme: AuthenticationScheme) -> anyhow::Result<()> {
        let Some(credentials) = &self.credentials else {
            return Ok(());
        };

        match scheme {
            AuthenticationScheme::Digest => {
                let uri = self.info.dst.to_string();

                let context = digest_auth::AuthContext::new_with_method(
                    &credentials.username,
                    &credentials.password,
                    &uri,
                    Option::<&'_ [u8]>::None,
                    digest_auth::HttpMethod::CONNECT,
                );

                let mut state = self.digest_state.lock().await;
                let response = state.as_mut().unwrap().respond(&context).unwrap();

                self.server_outbuf
                    .extend(format!("{}: {}\r\n", PROXY_AUTHORIZATION, response.to_header_string()).as_bytes());
            }
            AuthenticationScheme::Basic => {
                let cred = format!("{}:{}", credentials.username, credentials.password);
                let auth_b64 = base64::engine::general_purpose::STANDARD.encode(cred);
                self.server_outbuf
                    .extend(format!("{}: Basic {}\r\n", PROXY_AUTHORIZATION, auth_b64).as_bytes());
            }
            AuthenticationScheme::None => {}
        }

        Ok(())
    }

    #[async_recursion::async_recursion]
    async fn state_change(&mut self) -> anyhow::Result<()> {
        match self.state {
            HttpState::ExpectResponseHeaders => {
                while self.counter < self.server_inbuf.len() {
                    let b = self.server_inbuf[self.counter];
                    if b == b'\n' {
                        self.crlf_state += 1;
                    } else if b != b'\r' {
                        self.crlf_state = 0;
                    }

                    self.counter += 1;
                    if self.crlf_state == 2 {
                        break;
                    }
                }

                if self.crlf_state != 2 {
                    return Ok(());
                }

                self.counter = 0;
                self.crlf_state = 0;

                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut res = Response::new(&mut headers);

                let slice = self.server_inbuf.make_contiguous();
                let status = res.parse(slice)?;
                if status.is_partial() {
                    return Ok(());
                }
                let len = status.unwrap();
                let status_code = res.code.unwrap();
                let version = res.version.unwrap();

                if status_code == 200 {
                    self.state = HttpState::Established;
                    self.server_inbuf.clear();
                    return self.state_change().await;
                }

                if status_code != 407 {
                    let e = format!(
                        "Expected success status code. Server replied with {} [Reason: {}].",
                        status_code,
                        res.reason.unwrap()
                    );
                    bail!(e)
                }

                let headers_map: HashMap<UniCase<&str>, &[u8], RandomState> =
                    HashMap::from_iter(headers.map(|x| (UniCase::new(x.name), x.value)));

                let Some(auth_data) = headers_map.get(&UniCase::new(PROXY_AUTHENTICATE)) else {
                    bail!("Proxy requires auth but doesn't send it datails")
                };

                if !auth_data[..6].eq_ignore_ascii_case(b"digest") {
                    bail!("Bad credentials")
                }

                let data = str::from_utf8(auth_data)?;
                let state = digest_auth::parse(data)?;
                if self.before && !state.stale {
                    bail!("Bad credentials")
                }

                self.digest_state.lock().await.replace(state);
                self.before = true;

                let closed = match headers_map.get(&UniCase::new(CONNECTION)) {
                    Some(conn_header) => conn_header.eq_ignore_ascii_case(b"close"),
                    None => false,
                };

                if closed || version == 0 {
                    self.server_inbuf.clear();
                    self.server_outbuf.clear();
                    self.send_tunnel_request().await?;

                    self.state = HttpState::Reset;
                    return Ok(());
                }

                if headers_map.get(&UniCase::new(TRANSFER_ENCODING)).is_some() {
                    unimplemented!("Header Transfer-Encoding not supported");
                }

                let content_length = match headers_map.get(&UniCase::new(CONTENT_LENGTH)) {
                    Some(v) => {
                        let value = str::from_utf8(v)?;

                        match value.parse::<usize>() {
                            Ok(x) => x,
                            Err(_) => {
                                let mut it = value.split(',').map(|x| x.parse::<usize>());
                                let f = it.next().unwrap()?;
                                for k in it {
                                    if k? != f {
                                        bail!("Malformed response")
                                    }
                                }
                                f
                            }
                        }
                    }
                    None => {
                        self.server_inbuf.clear();
                        self.server_outbuf.clear();
                        self.send_tunnel_request().await?;

                        self.state = HttpState::Reset;
                        return Ok(());
                    }
                };

                self.state = HttpState::ExpectResponse;
                self.skip = content_length + len;

                return self.state_change().await;
            }
            HttpState::ExpectResponse => {
                if self.skip > 0 {
                    let cnt = self.skip.min(self.server_inbuf.len());
                    self.server_inbuf.drain(..cnt);
                    self.skip -= cnt;
                }

                if self.skip == 0 {
                    self.send_tunnel_request().await?;
                    self.state = HttpState::ExpectResponseHeaders;

                    return self.state_change().await;
                }
            }
            HttpState::Established => {
                self.client_outbuf.extend(self.server_inbuf.iter());
                self.server_outbuf.extend(self.client_inbuf.iter());
                self.server_inbuf.clear();
                self.client_inbuf.clear();
            }
            HttpState::Reset => {
                self.state = HttpState::ExpectResponseHeaders;
                return self.state_change().await;
            }
            _ => {}
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProxyHandler for HttpConnection {
    fn get_session_info(&self) -> SessionInfo {
        self.info.clone()
    }

    async fn push_data(&mut self, event: IncomingDataEvent<'_>) -> anyhow::Result<()> {
        let direction = event.direction;
        let buffer = event.buffer;
        match direction {
            IncomingDirection::FromServer => {
                self.server_inbuf.extend(buffer.iter());
            }
            IncomingDirection::FromClient => {
                self.client_inbuf.extend(buffer.iter());
            }
        }

        self.state_change().await?;
        Ok(())
    }

    fn consume_data(&mut self, dir: OutgoingDirection, size: usize) {
        let buffer = if dir == OutgoingDirection::ToServer {
            &mut self.server_outbuf
        } else {
            &mut self.client_outbuf
        };
        buffer.drain(0..size);
    }

    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent {
        let buffer = if dir == OutgoingDirection::ToServer {
            &mut self.server_outbuf
        } else {
            &mut self.client_outbuf
        };
        OutgoingDataEvent {
            direction: dir,
            buffer: buffer.make_contiguous(),
        }
    }

    fn connection_established(&self) -> bool {
        self.state == HttpState::Established
    }

    fn data_len(&self, dir: OutgoingDirection) -> usize {
        match dir {
            OutgoingDirection::ToServer => self.server_outbuf.len(),
            OutgoingDirection::ToClient => self.client_outbuf.len(),
        }
    }

    fn reset_connection(&self) -> bool {
        self.state == HttpState::Reset
    }

    fn get_udp_associate(&self) -> Option<SocketAddr> {
        None
    }
}

pub struct HttpManager {
    server: SocketAddr,
    credentials: Option<UserKey>,
    digest_state: Arc<Mutex<Option<DigestState>>>,
}

#[async_trait::async_trait]
impl ConnectionManager for HttpManager {
    async fn new_proxy_handler(&self, info: SessionInfo, _udp_associate: bool) -> anyhow::Result<Arc<Mutex<dyn ProxyHandler>>> {
        if info.protocol != IpProtocol::Tcp {
            bail!(Error::from("Invalid protocol"))
        }
        Ok(Arc::new(Mutex::new(
            HttpConnection::new(info, self.credentials.clone(), self.digest_state.clone()).await?,
        )))
    }

    fn get_server_addr(&self) -> SocketAddr {
        self.server
    }
}

impl HttpManager {
    pub fn new(server: SocketAddr, credentials: Option<UserKey>) -> Self {
        Self {
            server,
            credentials,
            digest_state: Arc::new(Mutex::new(None)),
        }
    }
}
