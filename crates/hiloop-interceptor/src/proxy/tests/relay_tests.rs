use super::*;
use crate::relay::{BoundHttpsSelector, SECRET_PROOF_HEADER};
use hudsucker::hyper::header::{AUTHORIZATION, CONNECTION, UPGRADE};
use std::time::Duration;

fn fixed_relay(proof_file: &std::path::Path) -> FixedTlsRelayConfig {
    let ca = ProxyCa::generate().expect("relay CA");
    FixedTlsRelayConfig::new(
        "127.0.0.1:8443".parse().expect("endpoint"),
        "secret-egress.test",
        vec![ca_trust_anchor(&ca)],
        proof_file.to_path_buf(),
        [BoundHttpsSelector::new("api.example.com").expect("selector")],
    )
    .expect("relay config")
}

async fn connected_handler(
    proof_file: &std::path::Path,
) -> (
    CaptureHandler,
    mpsc::Receiver<Result<RawSignal, SourceError>>,
    Arc<MemoryBlobStore>,
) {
    let (handler, rx, store) = handler_with(None, RedactionPolicy::disabled());
    let mut handler = handler.with_bound_https_relay(Some(fixed_relay(proof_file)));
    let connect = expect_forwarded(
        handler
            .on_request(connect_request("api.example.com:443"))
            .await,
    );
    assert_eq!(connect.method(), Method::CONNECT);
    (handler, rx, store)
}

#[tokio::test]
async fn bound_exchange_overwrites_private_headers_and_captures_only_safe_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"fresh-proof")
        .await
        .expect("proof");
    let (mut handler, mut rx, store) = connected_handler(&proof_file).await;
    let request = Request::builder()
        .method("POST")
        .uri("https://api.example.com:443/v1/items?query=CANARY")
        .header(HOST, "api.example.com:443")
        .header(AUTHORIZATION, "Bearer workload-forgery")
        .header(AUTHORIZATION, "Bearer appended-forgery")
        .header(SECRET_PROOF_HEADER, "forged-proof")
        .header("x-hiloop-private", "forged-private")
        .body(streaming_body(&[b"stream-1", b"stream-2"]))
        .expect("request");

    let forwarded = expect_forwarded(handler.on_request(request).await);
    assert_eq!(
        forwarded.uri().to_string(),
        "https://api.example.com:443/v1/items?query=CANARY"
    );
    assert_eq!(forwarded.headers()[HOST], "api.example.com:443");
    assert!(forwarded.headers().get(AUTHORIZATION).is_none());
    assert!(forwarded.headers().get("x-hiloop-private").is_none());
    assert_eq!(
        forwarded
            .headers()
            .get(SECRET_PROOF_HEADER)
            .map(hudsucker::hyper::header::HeaderValue::as_bytes),
        Some(b"fresh-proof".as_slice())
    );
    assert_eq!(
        drain_body(forwarded.into_body()).await.concat(),
        b"stream-1stream-2"
    );
    let request_signal = rx.recv().await.expect("request signal").expect("raw");

    let response = handler.on_response(
        Response::builder()
            .status(StatusCode::OK)
            .header(AUTHORIZATION, "Bearer reflected-secret")
            .header("location", "https://api.example.com/redirect/CANARY")
            .body(streaming_body(&[b"origin reflected CANARY"]))
            .expect("response"),
    );
    assert_eq!(response.headers()[AUTHORIZATION], "Bearer reflected-secret");
    assert_eq!(
        response.headers()["location"],
        "https://api.example.com/redirect/CANARY"
    );
    let _ = drain_body(response.into_body()).await;
    let response_signal = rx.recv().await.expect("response signal").expect("raw");

    assert!(store.blobs().is_empty());
    for signal in [&request_signal, &response_signal] {
        assert!(signal.body.is_empty());
        assert!(signal.payload_ref().is_none());
        assert!(!signal.attributes.contains_key("http.target"));
        assert!(!signal.attributes.contains_key(BODY_OMITTED_ATTR));
        assert!(!signal.attributes.contains_key(REQUEST_WIRE_SIZE_ATTR));
        assert!(!signal.attributes.contains_key(RESPONSE_WIRE_SIZE_ATTR));
        for canary in ["CANARY", "fresh-proof", "forged", "reflected-secret"] {
            assert!(
                signal
                    .attributes
                    .values()
                    .all(|value| !value.contains(canary)),
                "bound metadata must omit {canary}"
            );
        }
    }
    let mut request_keys = request_signal.attributes.keys().collect::<Vec<_>>();
    request_keys.sort_unstable();
    assert_eq!(
        request_keys,
        [
            EXCHANGE_ID_ATTR,
            "http.host",
            "http.method",
            "secret.egress.class",
        ]
    );
    let mut response_keys = response_signal.attributes.keys().collect::<Vec<_>>();
    response_keys.sort_unstable();
    assert_eq!(
        response_keys,
        [
            EXCHANGE_ID_ATTR,
            "http.host",
            "http.status_class",
            "secret.egress.class",
        ]
    );
    assert_eq!(
        request_signal.attributes[EXCHANGE_ID_ATTR],
        response_signal.attributes[EXCHANGE_ID_ATTR]
    );
    assert_eq!(response_signal.attributes["http.status_class"], "2xx");
    assert!(!response_signal.attributes.contains_key("http.status_code"));
}

#[tokio::test]
async fn proof_rotates_per_exchange_and_nonmatches_remain_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof-one")
        .await
        .expect("proof");
    let (connected, _rx, _store) = connected_handler(&proof_file).await;
    for proof in [b"proof-one".as_slice(), b"proof-two".as_slice()] {
        tokio::fs::write(&proof_file, proof)
            .await
            .expect("rotate proof");
        let mut exchange = connected.clone();
        let forwarded = expect_forwarded(
            exchange
                .on_request(
                    Request::builder()
                        .method("GET")
                        .uri("https://api.example.com/resource")
                        .header(HOST, "api.example.com")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await,
        );
        assert_eq!(
            forwarded
                .headers()
                .get(SECRET_PROOF_HEADER)
                .map(hudsucker::hyper::header::HeaderValue::as_bytes),
            Some(proof)
        );
    }

    let (handler, _rx, _store) = handler_with(None, RedactionPolicy::disabled());
    let mut handler = handler.with_bound_https_relay(Some(fixed_relay(&proof_file)));
    let forwarded = expect_forwarded(
        handler
            .on_request(
                Request::builder()
                    .method("GET")
                    .uri("https://other.example.com/path")
                    .header(AUTHORIZATION, "Bearer ordinary")
                    .header("x-hiloop-ordinary", "untouched")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await,
    );
    assert_eq!(forwarded.headers()[AUTHORIZATION], "Bearer ordinary");
    assert_eq!(forwarded.headers()["x-hiloop-ordinary"], "untouched");
    assert!(forwarded.headers().get(SECRET_PROOF_HEADER).is_none());
}

#[tokio::test]
async fn bound_request_scrubs_private_http2_trailers() {
    use hudsucker::hyper::body::Frame;

    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let (mut handler, _rx, _store) = connected_handler(&proof_file).await;
    let mut trailers = hudsucker::hyper::HeaderMap::new();
    trailers.insert(
        AUTHORIZATION,
        "Bearer trailer-secret".parse().expect("auth"),
    );
    trailers.insert(SECRET_PROOF_HEADER, "forged-proof".parse().expect("proof"));
    trailers.insert("x-hiloop-private", "private".parse().expect("private"));
    trailers.insert("x-safe-trailer", "preserved".parse().expect("safe"));
    let frames = futures_util::stream::iter([
        Ok::<_, hudsucker::Error>(Frame::data(Bytes::from_static(b"payload"))),
        Ok(Frame::trailers(trailers)),
    ]);
    let request = Request::builder()
        .method("POST")
        .uri("https://api.example.com/upload")
        .header(HOST, "api.example.com")
        .body(Body::from(StreamBody::new(frames)))
        .expect("request");

    let forwarded = expect_forwarded(handler.on_request(request).await);
    let mut frames = BodyStream::new(forwarded.into_body());
    assert_eq!(
        frames
            .next()
            .await
            .expect("data frame")
            .expect("data")
            .into_data()
            .expect("payload"),
        Bytes::from_static(b"payload")
    );
    let trailers = frames
        .next()
        .await
        .expect("trailer frame")
        .expect("trailers")
        .into_trailers()
        .expect("trailer map");
    assert!(trailers.get(AUTHORIZATION).is_none());
    assert!(trailers.get(SECRET_PROOF_HEADER).is_none());
    assert!(trailers.get("x-hiloop-private").is_none());
    assert_eq!(trailers["x-safe-trailer"], "preserved");
}

#[tokio::test]
async fn malformed_websocket_alternate_port_and_missing_proof_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let (handler, _rx, _store) = handler_with(None, RedactionPolicy::disabled());
    let mut handler = handler.with_bound_https_relay(Some(fixed_relay(&proof_file)));
    let mismatched_connect = Request::builder()
        .method(Method::CONNECT)
        .uri("api.example.com:443")
        .header(HOST, "other.example.com:443")
        .body(Body::empty())
        .expect("mismatched CONNECT");
    assert_eq!(
        expect_response(handler.on_request(mismatched_connect).await).status(),
        StatusCode::FORBIDDEN
    );

    let (connected, _rx, _store) = connected_handler(&proof_file).await;
    let requests = [
        Request::builder()
            .method(Method::CONNECT)
            .uri("other.example.com:443")
            .header(HOST, "other.example.com:443")
            .body(Body::empty())
            .expect("nested CONNECT"),
        Request::builder()
            .method("GET")
            .uri("/")
            .header(HOST, "api.example.com malformed")
            .body(Body::empty())
            .expect("malformed selected authority"),
        Request::builder()
            .method("GET")
            .uri("https://api.example.com:444/path")
            .header(HOST, "api.example.com:444")
            .body(Body::empty())
            .expect("alternate port"),
        Request::builder()
            .method("GET")
            .uri("https://api.example.com/path")
            .header(HOST, "api.example.com")
            .header(HOST, "api.example.com")
            .body(Body::empty())
            .expect("duplicate host"),
        Request::builder()
            .method("GET")
            .uri("https://api.example.com/path")
            .header(HOST, "api.example.com")
            .header(CONNECTION, "keep-alive, Upgrade")
            .header(UPGRADE, "websocket")
            .body(Body::empty())
            .expect("websocket"),
    ];
    for request in requests {
        let mut exchange = connected.clone();
        assert_eq!(
            expect_response(exchange.on_request(request).await).status(),
            StatusCode::FORBIDDEN
        );
    }

    tokio::fs::remove_file(&proof_file)
        .await
        .expect("remove proof");
    let mut exchange = connected;
    let denied = expect_response(
        exchange
            .on_request(
                Request::builder()
                    .method("GET")
                    .uri("https://api.example.com/path")
                    .header(HOST, "api.example.com")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await,
    );
    assert_eq!(denied.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn bound_upstream_abort_omits_target_and_error_detail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let (mut handler, mut rx, _store) = connected_handler(&proof_file).await;
    let forwarded = expect_forwarded(
        handler
            .on_request(
                Request::builder()
                    .method("GET")
                    .uri("https://api.example.com/private?credential=CANARY")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await,
    );
    let _ = forwarded
        .into_body()
        .collect()
        .await
        .expect("drain request");
    let _request = rx.recv().await.expect("request signal").expect("raw");

    handler
        .on_upstream_error("upstream_error", "relay leaked CANARY".to_owned())
        .await;
    let abort = rx.recv().await.expect("abort signal").expect("raw");
    assert_eq!(abort.kind, ABORT_KIND);
    assert!(!abort.attributes.contains_key("http.target"));
    assert!(!abort.attributes.contains_key(ABORT_DETAIL_ATTR));
    assert!(
        abort
            .attributes
            .values()
            .all(|value| !value.contains("CANARY"))
    );
}

#[derive(Debug)]
struct ObservedRelayRequest {
    method: Method,
    uri: hudsucker::hyper::Uri,
    version: hudsucker::hyper::Version,
    headers: hudsucker::hyper::HeaderMap,
}

async fn spawn_h2_relay(relay_ca: &ProxyCa) -> (SocketAddr, mpsc::Receiver<ObservedRelayRequest>) {
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let leaf = relay_ca
        .authority
        .gen_cert(&Authority::from_static("secret-egress.test"));
    let mut server_cfg =
        ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("server versions")
            .with_no_client_auth()
            .with_single_cert(vec![leaf], relay_ca.authority.private_key.clone_key())
            .expect("server cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind relay");
    let addr = listener.local_addr().expect("relay addr");
    let (observed_tx, observed_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let observed_tx = observed_tx.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service =
                    hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                        let observed_tx = observed_tx.clone();
                        async move {
                            let observed = ObservedRelayRequest {
                                method: request.method().clone(),
                                uri: request.uri().clone(),
                                version: request.version(),
                                headers: request.headers().clone(),
                            };
                            let _ = observed_tx.send(observed).await;
                            Ok::<_, std::convert::Infallible>(Response::new(StreamBody::new(
                                BodyStream::new(request.into_body()),
                            )))
                        }
                    });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (addr, observed_rx)
}

async fn spawn_bound_proxy(
    relay: FixedTlsRelayConfig,
) -> (
    SocketAddr,
    String,
    mpsc::Receiver<Result<RawSignal, SourceError>>,
    Arc<MemoryBlobStore>,
) {
    let store = Arc::new(MemoryBlobStore::default());
    let config = ProxySourceConfig::new(store.clone())
        .with_max_capture_bytes(None)
        .with_bound_https_relay(relay)
        .expect("bound relay config");
    let source = ProxySource::bind(Arc::new(HlcClock::new()), config)
        .await
        .expect("bind proxy");
    let addr = source.local_addr().expect("proxy addr");
    let ca_pem = source.ca_cert_pem().to_owned();
    let (signal_tx, signal_rx) = mpsc::channel(64);
    tokio::spawn(Box::new(source).run(
        RawSignalSink::new(signal_tx),
        Box::pin(std::future::pending()),
    ));
    (addr, ca_pem, signal_rx, store)
}

async fn connect_tunnel(proxy_addr: SocketAddr, authority: &str) -> tokio::net::TcpStream {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut tcp = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\nhost: {authority}\r\n\r\n").as_bytes())
        .await
        .expect("send CONNECT");
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        assert!(
            tcp.read(&mut byte).await.expect("CONNECT response") > 0,
            "proxy closed during CONNECT"
        );
        response.push(byte[0]);
    }
    assert!(response.starts_with(b"HTTP/1.1 200"));
    tcp
}

async fn connect_tunnel_without_host(
    proxy_addr: SocketAddr,
    authority: &str,
) -> tokio::net::TcpStream {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut tcp = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .expect("send CONNECT");
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        assert!(tcp.read(&mut byte).await.expect("CONNECT response") > 0);
        response.push(byte[0]);
    }
    assert!(response.starts_with(b"HTTP/1.1 200"));
    tcp
}

async fn h1_request_through_proxy(
    proxy_addr: SocketAddr,
    proxy_ca: &str,
    authority: &str,
    target: &str,
    host: &str,
) -> Vec<u8> {
    use hudsucker::rustls::pki_types::ServerName;
    use hudsucker::rustls::pki_types::pem::PemObject as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let tcp = connect_tunnel(proxy_addr, authority).await;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(proxy_ca.as_bytes()).expect("proxy CA der"))
        .expect("trust proxy CA");
    let mut config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(
        authority
            .split(':')
            .next()
            .expect("authority host")
            .to_owned(),
    )
    .expect("server name");
    let mut tls = connector.connect(server_name, tcp).await.expect("MITM TLS");
    tls.write_all(format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await
        .expect("send HTTP/1 request");
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        assert!(tls.read(&mut byte).await.expect("HTTP/1 response") > 0);
        response.push(byte[0]);
    }
    response
}

async fn client_hello(server_name: &str, send_sni: bool) -> Vec<u8> {
    use hudsucker::rustls::pki_types::ServerName;
    use tokio::io::AsyncReadExt as _;

    let mut config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config.enable_sni = send_sni;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let name = ServerName::try_from(server_name.to_owned()).expect("server name");
    let handshake = tokio::spawn(async move { connector.connect(name, client).await });
    let mut record = vec![0_u8; 5];
    server
        .read_exact(&mut record)
        .await
        .expect("TLS record header");
    let payload_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    record.resize(5 + payload_len, 0);
    server
        .read_exact(&mut record[5..])
        .await
        .expect("TLS ClientHello");
    handshake.abort();
    record
}

async fn blackhole_relay() -> (SocketAddr, mpsc::Receiver<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("blackhole relay");
    let addr = listener.local_addr().expect("blackhole address");
    let (accepted_tx, accepted_rx) = mpsc::channel(4);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = accepted_tx.send(()).await;
            tokio::spawn(async move {
                let _stream = stream;
                std::future::pending::<()>().await;
            });
        }
    });
    (addr, accepted_rx)
}

async fn named_loopback_observer(host: &str) -> (SocketAddr, mpsc::Receiver<()>) {
    let listener = TcpListener::bind((host, 0))
        .await
        .expect("bind named loopback observer");
    let addr = listener.local_addr().expect("named loopback address");
    let (accepted_tx, accepted_rx) = mpsc::channel(4);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = accepted_tx.send(()).await;
            tokio::spawn(async move {
                let _stream = stream;
                std::future::pending::<()>().await;
            });
        }
    });
    (addr, accepted_rx)
}

async fn strict_proxy(
    relay_addr: SocketAddr,
    selector: &str,
) -> (SocketAddr, String, tempfile::TempDir) {
    let relay_ca = ProxyCa::generate().expect("relay CA");
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let relay = FixedTlsRelayConfig::new(
        relay_addr,
        "secret-egress.test",
        vec![ca_trust_anchor(&relay_ca)],
        proof_file,
        [BoundHttpsSelector::new(selector).expect("selector")],
    )
    .expect("relay config");
    let (proxy, ca, _signals, _store) = spawn_bound_proxy(relay).await;
    (proxy, ca, dir)
}

#[tokio::test]
async fn fragmented_tls_and_unknown_prefaces_never_reach_an_upstream() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (relay_addr, mut relay_accepts) = blackhole_relay().await;

    let origin_host = "api.localhost";
    let (origin_addr, mut origin_accepts) = named_loopback_observer(origin_host).await;
    let origin_control = tokio::net::TcpStream::connect((origin_host, origin_addr.port()))
        .await
        .expect("selected origin is reachable by authority name");
    origin_accepts
        .recv()
        .await
        .expect("selected origin observes control connection");
    drop(origin_control);
    let relay_ca = ProxyCa::generate().expect("relay CA");
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let relay = FixedTlsRelayConfig::new(
        relay_addr,
        "secret-egress.test",
        vec![ca_trust_anchor(&relay_ca)],
        proof_file,
        [BoundHttpsSelector::new(origin_host).expect("selector")],
    )
    .expect("relay config")
    .with_bound_port_for_test(origin_addr.port());
    let (fragment_proxy, _ca, _signals, _store) = spawn_bound_proxy(relay).await;
    let authority = format!("{origin_host}:{}", origin_addr.port());
    let hello = client_hello(origin_host, true).await;
    let mut fragmented = connect_tunnel_without_host(fragment_proxy, &authority).await;
    fragmented.write_all(&hello[..1]).await.expect("first byte");
    tokio::time::sleep(Duration::from_millis(50)).await;
    fragmented.write_all(&hello[1..]).await.expect("hello tail");
    fragmented.shutdown().await.expect("finish hello");
    let mut closed = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), fragmented.read_to_end(&mut closed))
        .await
        .expect("fragmented connection closes")
        .expect("read close");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), origin_accepts.recv())
            .await
            .is_err(),
        "selected origin receives no raw fallback connection"
    );

    let mut unknown = connect_tunnel_without_host(fragment_proxy, &authority).await;
    unknown
        .write_all(b"SSH-2.0-arbitrary\r\n")
        .await
        .expect("unknown preface");
    unknown.shutdown().await.expect("finish unknown");
    tokio::time::timeout(Duration::from_secs(1), unknown.read_to_end(&mut closed))
        .await
        .expect("unknown connection closes")
        .expect("read close");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), origin_accepts.recv())
            .await
            .is_err(),
        "selected origin receives no unknown-preface fallback connection"
    );
    assert!(relay_accepts.try_recv().is_err(), "no relay connection");
}

#[tokio::test]
async fn missing_or_mismatched_client_hello_sni_fails_before_upstream() {
    use hudsucker::rustls::pki_types::ServerName;
    use hudsucker::rustls::pki_types::pem::PemObject as _;

    let (relay_addr, mut relay_accepts) = blackhole_relay().await;
    let (proxy_addr, proxy_ca, _dir) = strict_proxy(relay_addr, "api.example.com").await;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(proxy_ca.as_bytes()).expect("proxy CA der"))
        .expect("trust proxy CA");

    let tcp = connect_tunnel(proxy_addr, "api.example.com:443").await;
    let matching = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    let matching = tokio_rustls::TlsConnector::from(Arc::new(matching));
    assert!(
        matching
            .connect(
                ServerName::try_from("api.example.com").expect("matching server name"),
                tcp,
            )
            .await
            .is_ok(),
        "matching trusted SNI completes the MITM handshake"
    );

    for (name, send_sni) in [("other.example.com", true), ("api.example.com", false)] {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut tcp = connect_tunnel(proxy_addr, "api.example.com:443").await;
        tcp.write_all(&client_hello(name, send_sni).await)
            .await
            .expect("send invalid ClientHello");
        tcp.shutdown().await.expect("finish invalid ClientHello");
        let mut server_bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), tcp.read_to_end(&mut server_bytes))
            .await
            .expect("TLS rejection deadline")
            .expect("read TLS rejection");
        assert!(
            server_bytes.is_empty(),
            "invalid SNI is rejected before any certificate flight"
        );
    }
    assert!(relay_accepts.try_recv().is_err(), "no upstream connection");
}

#[tokio::test]
async fn http1_absolute_form_must_agree_with_the_selected_connect_authority() {
    let relay_ca = ProxyCa::generate().expect("relay CA");
    let (relay_addr, mut observed) = spawn_h2_relay(&relay_ca).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let relay = FixedTlsRelayConfig::new(
        relay_addr,
        "secret-egress.test",
        vec![ca_trust_anchor(&relay_ca)],
        proof_file,
        [BoundHttpsSelector::new("api.example.com").expect("selector")],
    )
    .expect("relay config");
    let (proxy_addr, proxy_ca, _signals, _store) = spawn_bound_proxy(relay).await;

    for target in [
        "https://other.example/private",
        "https://api.example.com:444/private",
    ] {
        let response = h1_request_through_proxy(
            proxy_addr,
            &proxy_ca,
            "api.example.com:443",
            target,
            "api.example.com:443",
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 403"), "target: {target}");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), observed.recv())
                .await
                .is_err(),
            "denied absolute target never reaches the relay: {target}"
        );
    }

    let response = h1_request_through_proxy(
        proxy_addr,
        &proxy_ca,
        "api.example.com:443",
        "https://api.example.com:443/allowed",
        "api.example.com:443",
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let request = observed.recv().await.expect("matching relay request");
    assert_eq!(
        request.uri.to_string(),
        "https://api.example.com:443/allowed"
    );
}

async fn response_blackhole_relay(relay_ca: &ProxyCa) -> (SocketAddr, mpsc::Receiver<()>) {
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let leaf = relay_ca
        .authority
        .gen_cert(&Authority::from_static("secret-egress.test"));
    let mut server_cfg =
        ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("server versions")
            .with_no_client_auth()
            .with_single_cert(vec![leaf], relay_ca.authority.private_key.clone_key())
            .expect("server cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind relay");
    let addr = listener.local_addr().expect("relay address");
    let (request_tx, request_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let request_tx = request_tx.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper::service::service_fn(move |request| {
                    let request_tx = request_tx.clone();
                    async move {
                        let body = request.into_body();
                        let _ = request_tx.send(()).await;
                        let response = std::future::pending::<
                            Result<Response<Body>, std::convert::Infallible>,
                        >()
                        .await;
                        drop(body);
                        response
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (addr, request_rx)
}

async fn early_response_relay(
    relay_ca: &ProxyCa,
    read_first_data: bool,
) -> (SocketAddr, mpsc::Receiver<()>) {
    use hudsucker::hyper::body::Frame;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let leaf = relay_ca
        .authority
        .gen_cert(&Authority::from_static("secret-egress.test"));
    let mut server_cfg =
        ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("server versions")
            .with_no_client_auth()
            .with_single_cert(vec![leaf], relay_ca.authority.private_key.clone_key())
            .expect("server cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind relay");
    let addr = listener.local_addr().expect("relay address");
    let (data_tx, data_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let data_tx = data_tx.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service =
                    hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                        let data_tx = data_tx.clone();
                        async move {
                            let mut request = BodyStream::new(request.into_body());
                            tokio::spawn(async move {
                                if read_first_data {
                                    while let Some(frame) = request.next().await {
                                        let frame = frame.expect("request frame");
                                        if frame.data_ref().is_some_and(|data| !data.is_empty()) {
                                            let _ = data_tx.send(()).await;
                                            break;
                                        }
                                    }
                                }
                                std::future::pending::<()>().await;
                            });
                            let body =
                                Body::from(StreamBody::new(futures_util::stream::pending::<
                                    Result<Frame<Bytes>, hudsucker::Error>,
                                >()));
                            Ok::<_, std::convert::Infallible>(Response::new(body))
                        }
                    });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (addr, data_rx)
}

async fn trailer_observing_relay(
    relay_ca: &ProxyCa,
) -> (
    SocketAddr,
    mpsc::Receiver<hudsucker::hyper::HeaderMap>,
    mpsc::Receiver<()>,
) {
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let leaf = relay_ca
        .authority
        .gen_cert(&Authority::from_static("secret-egress.test"));
    let mut server_cfg =
        ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("server versions")
            .with_no_client_auth()
            .with_single_cert(vec![leaf], relay_ca.authority.private_key.clone_key())
            .expect("server cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind relay");
    let addr = listener.local_addr().expect("relay address");
    let (trailers_tx, trailers_rx) = mpsc::channel(1);
    let (data_tx, data_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let trailers_tx = trailers_tx.clone();
            let data_tx = data_tx.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service =
                    hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                        let trailers_tx = trailers_tx.clone();
                        let data_tx = data_tx.clone();
                        async move {
                            let mut frames = BodyStream::new(request.into_body());
                            let mut trailers = hudsucker::hyper::HeaderMap::new();
                            while let Some(frame) = frames.next().await {
                                let frame = frame.expect("request frame");
                                if frame.data_ref().is_some() {
                                    let _ = data_tx.send(()).await;
                                }
                                if let Ok(value) = frame.into_trailers() {
                                    trailers = value;
                                }
                            }
                            let _ = trailers_tx.send(trailers).await;
                            Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
                        }
                    });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (addr, trailers_rx, data_rx)
}

#[tokio::test]
async fn private_http2_trailers_are_scrubbed_on_the_relay_wire() {
    use hudsucker::hyper::body::Frame;

    let relay_ca = ProxyCa::generate().expect("relay CA");
    let (relay_addr, mut observed, _data) = trailer_observing_relay(&relay_ca).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let relay = FixedTlsRelayConfig::new(
        relay_addr,
        "secret-egress.test",
        vec![ca_trust_anchor(&relay_ca)],
        proof_file,
        [BoundHttpsSelector::new("api.example.com").expect("selector")],
    )
    .expect("relay config");
    let (proxy_addr, proxy_ca, _signals, _store) = spawn_bound_proxy(relay).await;
    let mut sender = h2_client_through_proxy(proxy_addr, &proxy_ca, "api.example.com:443").await;
    let mut trailers = hudsucker::hyper::HeaderMap::new();
    trailers.insert(
        AUTHORIZATION,
        "Bearer secret".parse().expect("authorization"),
    );
    trailers.insert("x-hiloop-private", "secret".parse().expect("private"));
    trailers.insert("x-safe-trailer", "preserved".parse().expect("safe"));
    let (frames_tx, frames_rx) = mpsc::channel(2);
    let body = Body::from(StreamBody::new(
        tokio_stream::wrappers::ReceiverStream::new(frames_rx),
    ));
    let response = sender.send_request(
        Request::builder()
            .method("POST")
            .uri("https://api.example.com/upload")
            .body(body)
            .expect("request"),
    );
    frames_tx
        .send(Ok::<_, hudsucker::Error>(Frame::data(Bytes::from_static(
            b"payload",
        ))))
        .await
        .expect("data");
    frames_tx
        .send(Ok(Frame::trailers(trailers)))
        .await
        .expect("trailers");
    drop(frames_tx);
    assert_eq!(response.await.expect("response").status(), StatusCode::OK);
    let trailers = observed.recv().await.expect("relay trailers");
    assert!(trailers.get(AUTHORIZATION).is_none());
    assert!(trailers.get("x-hiloop-private").is_none());
    assert_eq!(trailers["x-safe-trailer"], "preserved");
}

#[tokio::test]
async fn slow_progressing_upload_may_receive_headers_after_request_eof() {
    use hudsucker::hyper::body::Frame;

    let relay_ca = ProxyCa::generate().expect("relay CA");
    let (relay_addr, mut observed, mut data) = trailer_observing_relay(&relay_ca).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let relay = FixedTlsRelayConfig::new(
        relay_addr,
        "secret-egress.test",
        vec![ca_trust_anchor(&relay_ca)],
        proof_file,
        [BoundHttpsSelector::new("api.example.com").expect("selector")],
    )
    .expect("relay config");
    let (proxy_addr, proxy_ca, _signals, _store) = spawn_bound_proxy(relay).await;
    let mut sender = h2_client_through_proxy(proxy_addr, &proxy_ca, "api.example.com:443").await;
    let (frames_tx, frames_rx) = mpsc::channel(4);
    let body = Body::from(StreamBody::new(
        tokio_stream::wrappers::ReceiverStream::new(frames_rx),
    ));
    let response = tokio::spawn(async move {
        sender
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://api.example.com/slow")
                    .body(body)
                    .expect("request"),
            )
            .await
    });
    for payload in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
        frames_tx
            .send(Ok::<_, hudsucker::Error>(Frame::data(
                Bytes::copy_from_slice(payload),
            )))
            .await
            .expect("progress frame");
        tokio::time::timeout(Duration::from_secs(3), data.recv())
            .await
            .expect("relay progress deadline")
            .expect("relay observed progress");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    drop(frames_tx);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), response)
            .await
            .expect("response deadline")
            .expect("request task")
            .expect("response")
            .status(),
        StatusCode::OK
    );
    observed.recv().await.expect("relay observed EOF");
}

#[tokio::test(start_paused = true)]
async fn relay_connect_and_tls_blackhole_has_a_fixed_deadline() {
    let (relay_addr, mut accepts) = blackhole_relay().await;
    let (proxy_addr, proxy_ca, _dir) = strict_proxy(relay_addr, "api.example.com").await;
    let mut sender = h2_client_through_proxy(proxy_addr, &proxy_ca, "api.example.com:443").await;
    let response = tokio::spawn(async move {
        sender
            .send_request(
                Request::builder()
                    .uri("https://api.example.com/deadline")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
    });
    accepts.recv().await.expect("relay TCP connect");
    tokio::time::advance(crate::relay::RELAY_CONNECT_TLS_TIMEOUT + Duration::from_millis(1)).await;
    assert_eq!(
        response
            .await
            .expect("request task")
            .expect("proxy response")
            .status(),
        StatusCode::BAD_GATEWAY
    );
}

#[tokio::test(start_paused = true)]
async fn relay_response_header_blackhole_has_a_fixed_deadline() {
    let relay_ca = ProxyCa::generate().expect("relay CA");
    let (relay_addr, mut requests) = response_blackhole_relay(&relay_ca).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let relay = FixedTlsRelayConfig::new(
        relay_addr,
        "secret-egress.test",
        vec![ca_trust_anchor(&relay_ca)],
        proof_file,
        [BoundHttpsSelector::new("api.example.com").expect("selector")],
    )
    .expect("relay config");
    let (proxy_addr, proxy_ca, _signals, _store) = spawn_bound_proxy(relay).await;
    let mut sender = h2_client_through_proxy(proxy_addr, &proxy_ca, "api.example.com:443").await;
    let response = tokio::spawn(async move {
        sender
            .send_request(
                Request::builder()
                    .uri("https://api.example.com/deadline")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
    });
    requests.recv().await.expect("relay request");
    tokio::time::advance(
        crate::bound_connect::RELAY_RESPONSE_HEADER_TIMEOUT + Duration::from_millis(1),
    )
    .await;
    assert_eq!(
        response
            .await
            .expect("request task")
            .expect("proxy response")
            .status(),
        StatusCode::BAD_GATEWAY
    );
}

#[tokio::test(start_paused = true)]
async fn relay_that_stops_polling_a_large_upload_hits_the_body_idle_deadline() {
    let relay_ca = ProxyCa::generate().expect("relay CA");
    let (relay_addr, mut requests) = response_blackhole_relay(&relay_ca).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let relay = FixedTlsRelayConfig::new(
        relay_addr,
        "secret-egress.test",
        vec![ca_trust_anchor(&relay_ca)],
        proof_file,
        [BoundHttpsSelector::new("api.example.com").expect("selector")],
    )
    .expect("relay config");
    let (proxy_addr, proxy_ca, _signals, _store) = spawn_bound_proxy(relay).await;
    let mut sender = h2_client_through_proxy(proxy_addr, &proxy_ca, "api.example.com:443").await;
    let body = Body::from(Bytes::from(vec![0_u8; 4 * 1024 * 1024]));
    let response = tokio::spawn(async move {
        sender
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://api.example.com/stalled-upload")
                    .body(body)
                    .expect("request"),
            )
            .await
    });
    requests.recv().await.expect("relay request headers");
    tokio::task::yield_now().await;
    assert!(
        !response.is_finished(),
        "relay holds the request body without polling it"
    );
    tokio::time::advance(
        crate::bound_connect::RELAY_REQUEST_BODY_IDLE_TIMEOUT
            .checked_sub(Duration::from_millis(1))
            .expect("idle deadline exceeds one millisecond"),
    )
    .await;
    tokio::task::yield_now().await;
    assert!(
        !response.is_finished(),
        "large upload remains pending before the idle deadline"
    );
    tokio::time::advance(Duration::from_millis(2)).await;
    assert_eq!(
        response
            .await
            .expect("request task")
            .expect("proxy response")
            .status(),
        StatusCode::BAD_GATEWAY
    );
}

#[tokio::test]
async fn early_response_keeps_supervising_a_later_stalled_upload() {
    use hudsucker::hyper::body::Frame;

    let relay_ca = ProxyCa::generate().expect("relay CA");
    let (relay_addr, mut first_data) = early_response_relay(&relay_ca, true).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let relay = FixedTlsRelayConfig::new(
        relay_addr,
        "secret-egress.test",
        vec![ca_trust_anchor(&relay_ca)],
        proof_file,
        [BoundHttpsSelector::new("api.example.com").expect("selector")],
    )
    .expect("relay config");
    let (proxy_addr, proxy_ca, _signals, _store) = spawn_bound_proxy(relay).await;
    let mut sender = h2_client_through_proxy(proxy_addr, &proxy_ca, "api.example.com:443").await;
    let (frames_tx, frames_rx) = mpsc::channel(4);
    let body = Body::from(StreamBody::new(
        tokio_stream::wrappers::ReceiverStream::new(frames_rx),
    ));
    let response = sender
        .send_request(
            Request::builder()
                .method("POST")
                .uri("https://api.example.com/early-response")
                .body(body)
                .expect("request"),
        )
        .await
        .expect("early response headers");
    assert_eq!(response.status(), StatusCode::OK);
    frames_tx
        .send(Ok::<_, hudsucker::Error>(Frame::data(Bytes::from(vec![
            1_u8;
            16 * 1024
        ]))))
        .await
        .expect("first upload chunk");
    first_data.recv().await.expect("relay reads first chunk");
    frames_tx
        .send(Ok(Frame::data(Bytes::from(vec![2_u8; 4 * 1024 * 1024]))))
        .await
        .expect("later upload");
    tokio::task::yield_now().await;
    tokio::time::pause();
    let response_body = tokio::spawn(async move {
        let mut frames = BodyStream::new(response.into_body());
        while let Some(frame) = frames.next().await {
            match frame {
                Ok(frame) if frame.data_ref().is_some_and(Bytes::is_empty) => {}
                Ok(_) => return false,
                Err(_) => return true,
            }
        }
        true
    });
    tokio::time::advance(
        crate::bound_connect::RELAY_REQUEST_BODY_IDLE_TIMEOUT
            .checked_sub(Duration::from_millis(1))
            .expect("idle deadline exceeds one millisecond"),
    )
    .await;
    tokio::task::yield_now().await;
    assert!(
        !response_body.is_finished(),
        "early response remains open before upload idle deadline"
    );
    tokio::time::advance(Duration::from_millis(2)).await;
    assert!(
        response_body.await.expect("response body task"),
        "stalled upload resets the early response stream"
    );
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(1), frames_tx.closed())
        .await
        .expect("stalled request body cancellation deadline");
}

#[tokio::test]
async fn empty_data_frames_do_not_refresh_the_upload_idle_deadline() {
    use hudsucker::hyper::body::Frame;

    let relay_ca = ProxyCa::generate().expect("relay CA");
    let (relay_addr, _first_data) = early_response_relay(&relay_ca, false).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let relay = FixedTlsRelayConfig::new(
        relay_addr,
        "secret-egress.test",
        vec![ca_trust_anchor(&relay_ca)],
        proof_file,
        [BoundHttpsSelector::new("api.example.com").expect("selector")],
    )
    .expect("relay config");
    let (proxy_addr, proxy_ca, _signals, _store) = spawn_bound_proxy(relay).await;
    let mut sender = h2_client_through_proxy(proxy_addr, &proxy_ca, "api.example.com:443").await;
    let (trigger_tx, trigger_rx) = mpsc::channel(1);
    let (polled_tx, mut polled_rx) = mpsc::channel(1);
    let frames = futures_util::stream::unfold(
        (trigger_rx, polled_tx),
        |(mut trigger_rx, polled_tx)| async move {
            trigger_rx.recv().await?;
            let _ = polled_tx.send(()).await;
            Some((
                Ok::<_, hudsucker::Error>(Frame::data(Bytes::new())),
                (trigger_rx, polled_tx),
            ))
        },
    );
    let response = sender
        .send_request(
            Request::builder()
                .method("POST")
                .uri("https://api.example.com/empty-progress")
                .body(Body::from(StreamBody::new(frames)))
                .expect("request"),
        )
        .await
        .expect("early response headers");
    tokio::time::pause();
    let response_body = tokio::spawn(async move {
        let mut frames = BodyStream::new(response.into_body());
        while let Some(frame) = frames.next().await {
            match frame {
                Ok(frame) if frame.data_ref().is_some_and(Bytes::is_empty) => {}
                Ok(_) => return false,
                Err(_) => return true,
            }
        }
        true
    });
    for step in 0..3 {
        trigger_tx.send(()).await.expect("empty frame trigger");
        polled_rx.recv().await.expect("empty frame was polled");
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        if step < 2 {
            assert!(
                !response_body.is_finished(),
                "empty frames must not move the original idle deadline"
            );
        }
    }
    assert!(
        response_body.await.expect("response body task"),
        "empty DATA frames cannot keep the response stream alive"
    );
}

#[tokio::test]
async fn exact_stream_uses_fixed_authenticated_tls_relay_and_rotates_proof() {
    let deadline = std::time::Duration::from_secs(30);
    let relay_ca = ProxyCa::generate().expect("relay CA");
    let (relay_addr, mut observed_rx) = spawn_h2_relay(&relay_ca).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof-one")
        .await
        .expect("proof");
    let relay = FixedTlsRelayConfig::new(
        relay_addr,
        "secret-egress.test",
        vec![ca_trust_anchor(&relay_ca)],
        proof_file.clone(),
        [BoundHttpsSelector::new("api.example.com").expect("selector")],
    )
    .expect("relay config");
    let (proxy_addr, proxy_ca_pem, mut signal_rx, store) = spawn_bound_proxy(relay).await;
    let mut sender =
        h2_client_through_proxy(proxy_addr, &proxy_ca_pem, "api.example.com:443").await;

    let (frame_tx, body) = channel_body();
    let response = sender.send_request(
        Request::builder()
            .method("POST")
            .uri("https://api.example.com:443/v1/items?query=REQUEST_CANARY")
            .header(HOST, "API.EXAMPLE.COM:443")
            .header(AUTHORIZATION, "Bearer workload-forgery")
            .header(SECRET_PROOF_HEADER, "forged-proof")
            .body(body)
            .expect("request"),
    );
    frame_tx
        .send(Bytes::from_static(b"stream-one,"))
        .await
        .expect("first frame");
    let response = tokio::time::timeout(deadline, response)
        .await
        .expect("headers before request EOF")
        .expect("response");
    let observed = observed_rx.recv().await.expect("relay observation");
    assert_eq!(observed.method, Method::POST);
    assert_eq!(observed.version, hudsucker::hyper::Version::HTTP_2);
    assert_eq!(
        observed.uri.authority().map(Authority::as_str),
        Some("api.example.com:443")
    );
    assert_eq!(
        observed
            .uri
            .path_and_query()
            .map(hyper::http::uri::PathAndQuery::as_str),
        Some("/v1/items?query=REQUEST_CANARY")
    );
    assert!(observed.headers.get(AUTHORIZATION).is_none());
    assert_eq!(observed.headers[HOST], "API.EXAMPLE.COM:443");
    assert_eq!(
        observed.headers[SECRET_PROOF_HEADER].as_bytes(),
        b"proof-one"
    );

    let mut echoed = BodyStream::new(response.into_body());
    assert_eq!(
        read_body_bytes(&mut echoed, b"stream-one,".len(), deadline).await,
        b"stream-one,"
    );
    frame_tx
        .send(Bytes::from_static(b"RESPONSE_CANARY"))
        .await
        .expect("second frame");
    assert_eq!(
        read_body_bytes(&mut echoed, b"RESPONSE_CANARY".len(), deadline).await,
        b"RESPONSE_CANARY"
    );
    drop(frame_tx);
    while tokio::time::timeout(deadline, echoed.next())
        .await
        .expect("response EOF")
        .is_some()
    {}

    tokio::fs::write(&proof_file, b"proof-two")
        .await
        .expect("rotate proof");
    let response = sender
        .send_request(
            Request::builder()
                .method("GET")
                .uri("https://api.example.com/rotated")
                .body(Body::empty())
                .expect("rotated request"),
        )
        .await
        .expect("rotated response");
    let observed = observed_rx.recv().await.expect("rotated observation");
    assert_eq!(
        observed.headers[SECRET_PROOF_HEADER].as_bytes(),
        b"proof-two"
    );
    let _ = response
        .into_body()
        .collect()
        .await
        .expect("drain response");

    for _ in 0..4 {
        let signal = tokio::time::timeout(deadline, signal_rx.recv())
            .await
            .expect("bound signal")
            .expect("signal")
            .expect("raw");
        assert!(signal.body.is_empty());
        assert!(signal.payload_ref().is_none());
        assert!(!signal.attributes.contains_key("http.target"));
        for canary in [
            "REQUEST_CANARY",
            "RESPONSE_CANARY",
            "proof-one",
            "proof-two",
        ] {
            assert!(
                signal
                    .attributes
                    .values()
                    .all(|value| !value.contains(canary)),
                "bound capture must omit {canary}"
            );
        }
    }
    assert!(store.blobs().is_empty());
}

#[tokio::test]
async fn relay_tls_identity_failure_never_falls_back_to_the_origin() {
    let deadline = std::time::Duration::from_secs(30);
    let relay_ca = ProxyCa::generate().expect("relay CA");
    let (relay_addr, mut observed_rx) = spawn_h2_relay(&relay_ca).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_file = dir.path().join("proof");
    tokio::fs::write(&proof_file, b"proof")
        .await
        .expect("proof");
    let relay = FixedTlsRelayConfig::new(
        relay_addr,
        "wrong-relay-identity.test",
        vec![ca_trust_anchor(&relay_ca)],
        proof_file,
        [BoundHttpsSelector::new("api.example.com").expect("selector")],
    )
    .expect("relay config");
    let (proxy_addr, proxy_ca_pem, _signal_rx, _store) = spawn_bound_proxy(relay).await;
    let mut sender =
        h2_client_through_proxy(proxy_addr, &proxy_ca_pem, "api.example.com:443").await;

    let outcome = tokio::time::timeout(
        deadline,
        sender.send_request(
            Request::builder()
                .method("GET")
                .uri("https://api.example.com/resource")
                .body(Body::empty())
                .expect("request"),
        ),
    )
    .await
    .expect("TLS failure returns promptly");
    if let Ok(response) = outcome {
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
    assert!(
        observed_rx.try_recv().is_err(),
        "the wrong relay identity must fail before any HTTP request, with no origin fallback"
    );
}
