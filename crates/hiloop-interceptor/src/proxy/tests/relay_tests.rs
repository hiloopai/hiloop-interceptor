use super::*;
use crate::relay::{BoundHttpsSelector, SECRET_PROOF_HEADER};
use hudsucker::hyper::header::{AUTHORIZATION, CONNECTION, UPGRADE};

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
            .header(HOST, "api.example.com:443")
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
