use async_trait::async_trait;
use hiloop_core::{
    event::Event,
    identity::{Hlc, RunContext},
};
use hiloop_interceptor::{
    CaptureSession,
    pipeline::PipelineOptions,
    seams::{
        ExportError, Exporter, NormalizationContext, NormalizerRouter, RawSignal, RawSignalSink,
        ShutdownSignal, Source, SourceError,
    },
    stdio::StdioLogNormalizer,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct Signals {
    signals: Vec<RawSignal>,
}

#[async_trait]
impl Source for Signals {
    fn name(&self) -> &'static str {
        "signals"
    }

    async fn run(
        self: Box<Self>,
        sink: RawSignalSink,
        _shutdown: ShutdownSignal,
    ) -> Result<(), SourceError> {
        for signal in self.signals {
            if !sink.send(signal).await.is_open() {
                break;
            }
        }
        Ok(())
    }
}

struct UntilShutdown {
    ready: tokio::sync::oneshot::Sender<()>,
    signal: RawSignal,
}

#[async_trait]
impl Source for UntilShutdown {
    fn name(&self) -> &'static str {
        "until-shutdown"
    }

    async fn run(
        self: Box<Self>,
        sink: RawSignalSink,
        shutdown: ShutdownSignal,
    ) -> Result<(), SourceError> {
        let Self { ready, signal } = *self;
        if sink.send(signal).await.is_open() {
            let _ = ready.send(());
            shutdown.await;
        }
        Ok(())
    }
}

#[derive(Default)]
struct RecordingExporter {
    events: Mutex<Vec<Event>>,
    flushes: AtomicUsize,
}

#[async_trait]
impl Exporter for RecordingExporter {
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        self.events
            .lock()
            .expect("event lock")
            .extend_from_slice(events);
        Ok(())
    }

    async fn flush(&self) -> Result<(), ExportError> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn stdout_signal(wall_ns: u64, body: &'static [u8]) -> RawSignal {
    RawSignal::new(
        "stdio",
        "stdout",
        Hlc {
            wall_ns,
            logical: 0,
        },
        body,
    )
}

#[tokio::test]
async fn one_session_accepts_sequential_and_long_lived_sources_then_flushes() {
    let options = PipelineOptions::new(2, 2, 1).expect("pipeline options");
    let session = CaptureSession::start(options);
    let control = session.control();
    let normalizer = StdioLogNormalizer;
    let router = NormalizerRouter::single(&normalizer);
    let exporter = Arc::new(RecordingExporter::default());
    let context = NormalizationContext::new(RunContext::new_local_root());

    let capture = session.finish(context, router, exporter.as_ref(), None);
    let sources = async {
        control
            .attach(Box::new(Signals {
                signals: vec![stdout_signal(1, b"first")],
            }))
            .expect("open session")
            .await
            .expect("first source");

        control
            .attach(Box::new(Signals {
                signals: vec![stdout_signal(2, b"second")],
            }))
            .expect("session remains open after one source ends")
            .await
            .expect("second source");

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = control
            .attach(Box::new(UntilShutdown {
                ready: ready_tx,
                signal: stdout_signal(3, b"server"),
            }))
            .expect("attach server source");
        let stop = async {
            ready_rx.await.expect("server emitted before shutdown");
            control.shutdown();
        };
        let (server_result, ()) = tokio::join!(server, stop);
        server_result.expect("server source shuts down cooperatively");
        assert!(matches!(
            control.attach(Box::new(Signals {
                signals: vec![stdout_signal(4, b"late")],
            })),
            Err(hiloop_interceptor::CaptureSessionError::Closed)
        ));
    };

    let (report, ()) = tokio::join!(capture, sources);
    let report = report.expect("capture session finishes");

    assert_eq!(report.raw_signals, 3);
    assert_eq!(report.events, 3);
    assert_eq!(exporter.events.lock().expect("event lock").len(), 3);
    assert_eq!(exporter.flushes.load(Ordering::SeqCst), 1);
}
