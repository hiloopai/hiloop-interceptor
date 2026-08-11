//! Fail-closed CONNECT transport for proof-bound HTTPS destinations.

use std::{convert::Infallible, sync::Arc, time::Duration};

use futures_util::StreamExt as _;
use http_body_util::{BodyStream, StreamBody};
use hudsucker::{
    Body, RequestOrResponse,
    certificate_authority::CertificateAuthority,
    hyper::{Request, Response, StatusCode, Uri, http::uri::Authority, service::service_fn},
    hyper_util::{
        client::legacy::Client,
        rt::{TokioExecutor, TokioIo},
        server::conn::auto::Builder as ServerBuilder,
    },
};
use tokio_rustls::LazyConfigAcceptor;

use crate::{
    egress::canonicalize_host,
    proxy::{CaptureHandler, ProxyAuthority},
    relay::RelayRoutingConnector,
};

pub(crate) const TLS_CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const RELAY_REQUEST_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const RELAY_RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_BODY_PROGRESS_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy)]
enum RequestBodyState {
    Progress(tokio::time::Instant),
    Complete,
}

#[derive(Clone)]
pub(crate) struct BoundConnectTransport {
    authority: Arc<ProxyAuthority>,
    client: Client<RelayRoutingConnector, Body>,
    server: ServerBuilder<TokioExecutor>,
}

impl BoundConnectTransport {
    pub(crate) fn new(authority: Arc<ProxyAuthority>, connector: RelayRoutingConnector) -> Self {
        let mut client_builder = Client::builder(TokioExecutor::new());
        client_builder
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true);
        let mut server = ServerBuilder::new(TokioExecutor::new());
        server
            .http1()
            .title_case_headers(true)
            .preserve_header_case(true);
        Self {
            authority,
            client: client_builder.build(connector),
            server,
        }
    }

    pub(crate) fn spawn(
        self: Arc<Self>,
        upgrade: hudsucker::hyper::upgrade::OnUpgrade,
        authority: Authority,
        handler: CaptureHandler,
    ) {
        tokio::spawn(async move {
            if self.serve(upgrade, authority, handler).await.is_err() {
                eprintln!("hiloop-interceptor: bound secret CONNECT failed");
            }
        });
    }

    async fn serve(
        &self,
        upgrade: hudsucker::hyper::upgrade::OnUpgrade,
        authority: Authority,
        handler: CaptureHandler,
    ) -> Result<(), ()> {
        let upgraded = tokio::time::timeout(TLS_CLIENT_HELLO_TIMEOUT, upgrade)
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        let upgraded = TokioIo::new(upgraded);
        let start = tokio::time::timeout(
            TLS_CLIENT_HELLO_TIMEOUT,
            LazyConfigAcceptor::new(hudsucker::rustls::server::Acceptor::default(), upgraded),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

        let connect = canonicalize_host(authority.as_str()).map_err(|_| ())?;
        let sni = start
            .client_hello()
            .server_name()
            .ok_or(())
            .and_then(|name| canonicalize_host(name).map_err(|_| ()))?;
        if connect.host() != sni.host() {
            return Err(());
        }

        let server_config = self.authority.gen_server_config(&authority).await;
        let tls = tokio::time::timeout(TLS_CLIENT_HELLO_TIMEOUT, start.into_stream(server_config))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        let client = self.client.clone();
        let service = service_fn(move |request| {
            forward_bound_request(request, authority.clone(), handler.clone(), client.clone())
        });
        self.server
            .serve_connection_with_upgrades(TokioIo::new(tls), service)
            .await
            .map_err(|_| ())
    }
}

async fn forward_bound_request(
    mut request: Request<hudsucker::hyper::body::Incoming>,
    authority: Authority,
    mut handler: CaptureHandler,
    client: Client<RelayRoutingConnector, Body>,
) -> Result<Response<Body>, Infallible> {
    if matches!(
        request.version(),
        hudsucker::hyper::Version::HTTP_10 | hudsucker::hyper::Version::HTTP_11
    ) {
        let (mut parts, body) = request.into_parts();
        match (parts.uri.scheme(), parts.uri.authority()) {
            (None, None) if parts.uri.path().starts_with('/') => {
                let mut uri = parts.uri.into_parts();
                uri.scheme = Some(hudsucker::hyper::http::uri::Scheme::HTTPS);
                uri.authority = Some(authority);
                let Ok(uri) = Uri::from_parts(uri) else {
                    return Ok(forbidden());
                };
                parts.uri = uri;
            }
            (Some(_), Some(_)) => {}
            _ => return Ok(forbidden()),
        }
        request = Request::from_parts(parts, body);
    }

    let request = request.map(Body::from);
    let request = match handler.on_request(request).await {
        RequestOrResponse::Request(request) => request,
        RequestOrResponse::Response(response) => return Ok(response),
    };
    let (parts, body) = request.into_parts();
    let (body, mut body_state, request_abort) = request_body_with_progress(body);
    let mut response = Box::pin(client.request(Request::from_parts(parts, body)));
    let outcome = loop {
        let state = *body_state.borrow_and_update();
        let deadline = match state {
            RequestBodyState::Progress(at) => at + RELAY_REQUEST_BODY_IDLE_TIMEOUT,
            RequestBodyState::Complete => {
                break tokio::time::timeout(RELAY_RESPONSE_HEADER_TIMEOUT, &mut response)
                    .await
                    .ok();
            }
        };
        tokio::select! {
            biased;
            result = &mut response => break Some(result),
            changed = body_state.changed() => {
                if changed.is_err() {
                    break tokio::time::timeout(RELAY_RESPONSE_HEADER_TIMEOUT, &mut response)
                        .await
                        .ok();
                }
            }
            () = tokio::time::sleep_until(deadline) => break None,
        }
    };
    match outcome {
        Some(Ok(response)) => {
            let (parts, body) = response.map(Body::from).into_parts();
            let body = supervise_response_body(body, body_state, request_abort);
            Ok(handler.on_response(Response::from_parts(parts, body)))
        }
        Some(Err(error)) => {
            request_abort.abort();
            Ok(handler.on_upstream_client_error(error).await)
        }
        None => {
            request_abort.abort();
            eprintln!("hiloop-interceptor: bound secret relay request timed out");
            handler
                .on_upstream_error("upstream_error", "relay request timed out".to_owned())
                .await;
            Ok(bad_gateway())
        }
    }
}

fn request_body_with_progress(
    body: Body,
) -> (
    Body,
    tokio::sync::watch::Receiver<RequestBodyState>,
    tokio::task::AbortHandle,
) {
    let (frame_tx, frame_rx) = tokio::sync::mpsc::channel(1);
    let pump = tokio::spawn(async move {
        let mut frames = BodyStream::new(body);
        while let Some(frame) = frames.next().await {
            match frame {
                Ok(frame) => match frame.into_data() {
                    Ok(data) if data.is_empty() => {
                        if frame_tx
                            .send(Ok(hudsucker::hyper::body::Frame::data(data)))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(mut data) => {
                        while !data.is_empty() {
                            let chunk =
                                data.split_to(data.len().min(RELAY_BODY_PROGRESS_CHUNK_BYTES));
                            if frame_tx
                                .send(Ok(hudsucker::hyper::body::Frame::data(chunk)))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    Err(frame) => {
                        let _ = frame_tx.send(Ok(frame)).await;
                        return;
                    }
                },
                Err(error) => {
                    let _ = frame_tx.send(Err(error)).await;
                    return;
                }
            }
        }
    });
    let request_abort = pump.abort_handle();
    let (state_tx, state_rx) =
        tokio::sync::watch::channel(RequestBodyState::Progress(tokio::time::Instant::now()));
    let frames = futures_util::stream::unfold(
        (
            tokio_stream::wrappers::ReceiverStream::new(frame_rx),
            state_tx,
        ),
        |(mut frames, state_tx)| async move {
            match frames.next().await {
                Some(Ok(frame)) => {
                    if frame.data_ref().is_some_and(|data| !data.is_empty()) {
                        state_tx
                            .send_replace(RequestBodyState::Progress(tokio::time::Instant::now()));
                    } else if frame.trailers_ref().is_some() {
                        state_tx.send_replace(RequestBodyState::Complete);
                    }
                    Some((Ok(frame), (frames, state_tx)))
                }
                Some(Err(error)) => {
                    state_tx.send_replace(RequestBodyState::Complete);
                    Some((Err(error), (frames, state_tx)))
                }
                None => {
                    state_tx.send_replace(RequestBodyState::Complete);
                    None
                }
            }
        },
    );
    (Body::from(StreamBody::new(frames)), state_rx, request_abort)
}

fn supervise_response_body(
    body: Body,
    mut body_state: tokio::sync::watch::Receiver<RequestBodyState>,
    request_abort: tokio::task::AbortHandle,
) -> Body {
    let (frame_tx, frame_rx) = tokio::sync::mpsc::channel(1);
    let (timeout_tx, timeout_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let mut frames = BodyStream::new(body);
        let mut pending = None;
        loop {
            let state = *body_state.borrow_and_update();
            if matches!(state, RequestBodyState::Complete) {
                if let Some(frame) = pending.take()
                    && frame_tx.send(frame).await.is_err()
                {
                    return;
                }
                while let Some(frame) = frames.next().await {
                    if frame_tx.send(frame).await.is_err() {
                        return;
                    }
                }
                return;
            }
            let RequestBodyState::Progress(at) = state else {
                unreachable!("complete request bodies are handled above")
            };
            let deadline = at + RELAY_REQUEST_BODY_IDLE_TIMEOUT;
            tokio::select! {
                biased;
                changed = body_state.changed() => {
                    if changed.is_err() {
                        request_abort.abort();
                        while let Some(frame) = frames.next().await {
                            if frame_tx.send(frame).await.is_err() {
                                return;
                            }
                        }
                        return;
                    }
                }
                permit = frame_tx.reserve(), if pending.is_some() => {
                    let Ok(permit) = permit else {
                        return;
                    };
                    permit.send(pending.take().expect("guarded response frame"));
                }
                frame = frames.next(), if pending.is_none() => {
                    match frame {
                        Some(Ok(frame)) => pending = Some(Ok(frame)),
                        Some(Err(error)) => {
                            request_abort.abort();
                            let _ = frame_tx.send(Err(error)).await;
                            return;
                        }
                        None => {
                            request_abort.abort();
                            return;
                        }
                    }
                }
                () = tokio::time::sleep_until(deadline) => {
                    eprintln!("hiloop-interceptor: bound secret relay upload timed out");
                    request_abort.abort();
                    timeout_tx.send_replace(true);
                    return;
                }
            }
        }
    });
    let frames = futures_util::stream::unfold(
        (
            tokio_stream::wrappers::ReceiverStream::new(frame_rx),
            timeout_rx,
            true,
            false,
        ),
        |(mut frames, mut timeout, mut timeout_open, done)| async move {
            if done {
                return None;
            }
            loop {
                if *timeout.borrow_and_update() {
                    let error = hudsucker::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "bound relay upload timed out",
                    ));
                    return Some((Err(error), (frames, timeout, timeout_open, true)));
                }
                if !timeout_open {
                    return frames
                        .next()
                        .await
                        .map(|frame| (frame, (frames, timeout, false, false)));
                }
                tokio::select! {
                    biased;
                    changed = timeout.changed() => {
                        if changed.is_err() {
                            timeout_open = false;
                        }
                    }
                    frame = frames.next() => {
                        return frame.map(|frame| (frame, (frames, timeout, timeout_open, false)));
                    }
                }
            }
        },
    );
    Body::from(StreamBody::new(frames))
}

fn forbidden() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::empty())
        .expect("static response")
}

fn bad_gateway() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::empty())
        .expect("static response")
}
