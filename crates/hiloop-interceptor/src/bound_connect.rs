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
pub(crate) const RELAY_RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(5);

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
        let mut uri = parts.uri.into_parts();
        uri.scheme = Some(hudsucker::hyper::http::uri::Scheme::HTTPS);
        uri.authority = Some(authority);
        let Ok(uri) = Uri::from_parts(uri) else {
            return Ok(forbidden());
        };
        parts.uri = uri;
        request = Request::from_parts(parts, body);
    }

    let request = request.map(Body::from);
    let request = match handler.on_request(request).await {
        RequestOrResponse::Request(request) => request,
        RequestOrResponse::Response(response) => return Ok(response),
    };
    let (parts, body) = request.into_parts();
    let (body, completion) = request_body_with_completion(body);
    let mut response = Box::pin(client.request(Request::from_parts(parts, body)));
    let outcome = tokio::select! {
        result = &mut response => Some(result),
        _ = completion => tokio::time::timeout(RELAY_RESPONSE_HEADER_TIMEOUT, &mut response)
            .await
            .ok(),
    };
    match outcome {
        Some(Ok(response)) => Ok(handler.on_response(response.map(Body::from))),
        Some(Err(error)) => Ok(handler.on_upstream_client_error(error).await),
        None => {
            eprintln!("hiloop-interceptor: bound secret relay response timed out");
            handler
                .on_upstream_error("upstream_error", "relay response timed out".to_owned())
                .await;
            Ok(bad_gateway())
        }
    }
}

fn request_body_with_completion(body: Body) -> (Body, tokio::sync::oneshot::Receiver<()>) {
    let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
    let frames = futures_util::stream::unfold(
        (BodyStream::new(body), Some(completion_tx)),
        |(mut frames, mut completion_tx)| async move {
            if let Some(frame) = frames.next().await {
                return Some((frame, (frames, completion_tx)));
            }
            if let Some(completion_tx) = completion_tx.take() {
                let _ = completion_tx.send(());
            }
            None
        },
    );
    (Body::from(StreamBody::new(frames)), completion_rx)
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
