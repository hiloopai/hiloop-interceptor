//! Capture lifetime shared by local commands and sandbox runtimes.

use crate::{
    pipeline::{Pipeline, PipelineError, PipelineOptions, PipelineReport},
    seams::{
        Exporter, NormalizationContext, NormalizerRouter, RawSignal, RawSignalSink, RawStore,
        ShutdownSignal, Source, SourceError,
    },
};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;

/// One capture pipeline whose lifetime is independent of any individual process.
///
/// Create the session before starting captured work, clone its [`CaptureControl`]
/// into the adapters that discover sources, and poll [`finish`](Self::finish) for
/// the whole capture lifetime. The session drains and flushes only after
/// [`CaptureControl::shutdown`] asks every attached source to stop.
pub struct CaptureSession {
    signal_rx: mpsc::Receiver<Result<RawSignal, SourceError>>,
    control: CaptureControl,
    options: PipelineOptions,
}

impl CaptureSession {
    /// Start a bounded capture session.
    pub fn start(options: PipelineOptions) -> Self {
        let (signal_tx, signal_rx) = mpsc::channel(options.raw_queue_capacity());
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        Self {
            signal_rx,
            control: CaptureControl {
                inner: Arc::new(ControlInner {
                    signal_tx: Mutex::new(Some(signal_tx)),
                    shutdown_tx,
                }),
            },
            options,
        }
    }

    /// A cloneable attachment and shutdown handle for runtime adapters.
    pub fn control(&self) -> CaptureControl {
        self.control.clone()
    }

    /// Drive normalization and export until shutdown has drained every producer.
    pub async fn finish<E>(
        self,
        context: impl Into<NormalizationContext>,
        router: NormalizerRouter<'_>,
        exporter: &E,
        raw_store: Option<&dyn RawStore>,
    ) -> Result<PipelineReport, PipelineError>
    where
        E: Exporter,
    {
        let Self {
            signal_rx,
            control,
            options,
        } = self;
        let _shutdown_on_drop = ShutdownOnDrop(control);
        let stream = ReceiverStream::new(signal_rx);
        let mut pipeline = Pipeline::with_router(context, router, exporter).options(options);
        if let Some(raw_store) = raw_store {
            pipeline = pipeline.raw_store(raw_store);
        }
        pipeline.run(stream).await
    }
}

struct ControlInner {
    signal_tx: Mutex<Option<mpsc::Sender<Result<RawSignal, SourceError>>>>,
    shutdown_tx: watch::Sender<bool>,
}

/// Attaches capture sources and closes their shared session.
#[derive(Clone)]
pub struct CaptureControl {
    inner: Arc<ControlInner>,
}

impl CaptureControl {
    /// Prepare a source to run against this session.
    ///
    /// The returned future is deliberately not spawned: the lifecycle owner
    /// chooses where it runs and observes its result directly.
    pub fn attach(&self, source: Box<dyn Source>) -> Result<SourceHandle, CaptureSessionError> {
        let sink = RawSignalSink::new(self.signal_sender()?);
        let shutdown = shutdown_signal(self.inner.shutdown_tx.subscribe());
        let name = source.name();
        Ok(SourceHandle {
            name,
            future: Box::pin(source.run(sink, shutdown)),
        })
    }

    /// Ask every attached source to stop, then close the pipeline once they drain.
    pub fn shutdown(&self) {
        self.inner
            .signal_tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        self.inner.shutdown_tx.send_replace(true);
    }

    pub(crate) fn signal_sender(
        &self,
    ) -> Result<mpsc::Sender<Result<RawSignal, SourceError>>, CaptureSessionError> {
        self.inner
            .signal_tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(CaptureSessionError::Closed)
    }
}

fn shutdown_signal(mut shutdown_rx: watch::Receiver<bool>) -> ShutdownSignal {
    Box::pin(async move {
        if *shutdown_rx.borrow() {
            return;
        }
        while shutdown_rx.changed().await.is_ok() {
            if *shutdown_rx.borrow() {
                return;
            }
        }
    })
}

/// A source attached to a [`CaptureSession`].
#[must_use = "an attached source only captures while its future is polled"]
pub struct SourceHandle {
    name: &'static str,
    future: Pin<Box<dyn Future<Output = Result<(), SourceError>> + Send>>,
}

impl SourceHandle {
    /// Stable source name used for diagnostics.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl Future for SourceHandle {
    type Output = Result<(), SourceError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

/// Failure to attach work to a capture session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CaptureSessionError {
    /// The lifecycle owner has already begun shutdown.
    #[error("capture session is closed")]
    Closed,
}

struct ShutdownOnDrop(CaptureControl);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_state_is_durable_without_an_attached_source() {
        let session = CaptureSession::start(PipelineOptions::default());
        let control = session.control();
        assert_eq!(control.inner.shutdown_tx.receiver_count(), 0);

        control.shutdown();

        assert!(*control.inner.shutdown_tx.subscribe().borrow());
    }
}
