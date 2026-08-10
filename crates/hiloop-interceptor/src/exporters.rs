//! Local exporters used by the interceptor runtime and tests.

use crate::jsonl::JsonlWriter;
use crate::seams::{ExportError, Exporter};
use async_trait::async_trait;
use futures_util::future::join_all;
use hiloop_core::{capture::CaptureCompletionReport, event::Event};
use std::{io, path::Path};

/// Writes normalized events as newline-delimited JSON.
#[derive(Debug)]
pub struct JsonlExporter {
    writer: JsonlWriter,
}

impl JsonlExporter {
    /// Creates a JSONL output file, failing if the path already exists.
    pub async fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            writer: JsonlWriter::create(path).await?,
        })
    }
}

#[async_trait]
impl Exporter for JsonlExporter {
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        for event in events {
            let line = serde_json::to_vec(event).map_err(jsonl_error)?;
            self.writer
                .write_line(&line)
                .await
                .map_err(|error| io_error("failed to write event", error))?;
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), ExportError> {
        self.writer
            .flush()
            .await
            .map_err(|error| io_error("failed to flush events", error))
    }
}

fn io_error(message: &'static str, error: io::Error) -> ExportError {
    ExportError::with_source("jsonl", message, error)
}

fn jsonl_error(error: serde_json::Error) -> ExportError {
    ExportError::with_source("jsonl", "failed to encode event as JSON", error)
}

/// Sends each batch to independent sinks (e.g. a local JSONL log plus remote gRPC) from one
/// capture pipeline. Every sink is attempted even when a sibling fails; the first error is
/// returned after all attempts settle.
pub struct FanOutExporter {
    exporters: Vec<Box<dyn Exporter>>,
}

impl FanOutExporter {
    #[must_use]
    pub fn new(exporters: Vec<Box<dyn Exporter>>) -> Self {
        Self { exporters }
    }
}

#[async_trait]
impl Exporter for FanOutExporter {
    async fn export(&self, events: &[Event]) -> Result<(), ExportError> {
        first_error(
            join_all(
                self.exporters
                    .iter()
                    .map(|exporter| exporter.export(events)),
            )
            .await,
        )
    }

    async fn flush(&self) -> Result<(), ExportError> {
        first_error(join_all(self.exporters.iter().map(|exporter| exporter.flush())).await)
    }

    async fn export_completion(
        &self,
        event: &Event,
        report: &CaptureCompletionReport,
    ) -> Result<(), ExportError> {
        first_error(
            join_all(
                self.exporters
                    .iter()
                    .map(|exporter| exporter.export_completion(event, report)),
            )
            .await,
        )
    }
}

fn first_error(results: Vec<Result<(), ExportError>>) -> Result<(), ExportError> {
    results
        .into_iter()
        .find_map(Result::err)
        .map_or(Ok(()), Err)
}

#[cfg(test)]
pub(crate) mod testing {
    use hiloop_core::{
        event::{AttributeKey, Event, EventName, SignalType},
        identity::{Hlc, RunContext},
    };

    pub(crate) fn sample_log_event() -> Event {
        Event::new(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            SignalType::Log,
            EventName::new("process.stdout").expect("event name"),
        )
        .with_attribute(
            AttributeKey::new("message").expect("attribute key"),
            "hello",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{testing::sample_log_event, *};
    use crate::seams::{Exporter, testing::MemoryExporter};
    use crate::spool::{SpoolPolicy, SpoolingExporter};
    use hiloop_core::{
        capture::{
            CaptureCompletionReport, CaptureEventDelivery, CaptureEvidenceTrust,
            CaptureSourceReport, CaptureSourcesReport,
        },
        identity::{Hlc, RunContext},
    };
    use serde_json::Value;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct CompletionRecorder {
        records: Mutex<Vec<(Value, Value)>>,
    }

    struct RejectingExporter;

    #[async_trait]
    impl Exporter for RejectingExporter {
        async fn export(&self, _events: &[Event]) -> Result<(), ExportError> {
            Err(ExportError::rejected("fixture", "rejected event"))
        }

        async fn export_completion(
            &self,
            _event: &Event,
            _report: &CaptureCompletionReport,
        ) -> Result<(), ExportError> {
            Err(ExportError::rejected("fixture", "rejected completion"))
        }
    }

    #[async_trait]
    impl Exporter for CompletionRecorder {
        async fn export(&self, _events: &[Event]) -> Result<(), ExportError> {
            Ok(())
        }

        async fn export_completion(
            &self,
            event: &Event,
            report: &CaptureCompletionReport,
        ) -> Result<(), ExportError> {
            self.records.lock().expect("records").push((
                serde_json::to_value(event).expect("event json"),
                serde_json::to_value(report).expect("report json"),
            ));
            Ok(())
        }
    }

    async fn assert_exporter_accepts_empty_batch_and_flushes<E>(exporter: &E)
    where
        E: Exporter,
    {
        exporter
            .export(&[])
            .await
            .expect("empty batch should succeed");
        exporter
            .export(&[sample_log_event()])
            .await
            .expect("event batch should succeed");
        exporter.flush().await.expect("flush should succeed");
    }

    #[tokio::test]
    async fn memory_exporter_satisfies_exporter_contract() {
        let exporter = MemoryExporter::default();

        assert_exporter_accepts_empty_batch_and_flushes(&exporter).await;

        assert_eq!(exporter.events().len(), 1);
    }

    /// A shared handle satisfies the same contract and exports through the shared
    /// instance (the supervisor fans out through one while keeping the other).
    #[tokio::test]
    async fn arc_exporter_satisfies_exporter_contract_through_the_shared_instance() {
        let exporter = std::sync::Arc::new(MemoryExporter::default());

        assert_exporter_accepts_empty_batch_and_flushes(&std::sync::Arc::clone(&exporter)).await;

        assert_eq!(exporter.events().len(), 1);
    }

    #[tokio::test]
    async fn jsonl_exporter_satisfies_exporter_contract() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("events.jsonl");
        let exporter = JsonlExporter::create(&path).await.expect("create exporter");

        assert_exporter_accepts_empty_batch_and_flushes(&exporter).await;

        let contents = tokio::fs::read_to_string(path).await.expect("read jsonl");
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);

        let event = serde_json::from_str::<Value>(lines[0]).expect("event json");
        assert_eq!(event["signal"], "log");
        assert_eq!(event["name"], "process.stdout");
        assert_eq!(event["attributes"]["message"], "hello");
    }

    #[tokio::test]
    async fn jsonl_exporter_refuses_to_overwrite_existing_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("events.jsonl");
        tokio::fs::write(&path, "existing")
            .await
            .expect("seed file");

        let error = JsonlExporter::create(&path)
            .await
            .expect_err("existing file should not be overwritten");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        let contents = tokio::fs::read_to_string(path).await.expect("read file");
        assert_eq!(contents, "existing");
    }

    #[tokio::test]
    async fn fanout_delivers_one_canonical_completion_projection_to_every_sink() {
        let direct = Arc::new(CompletionRecorder::default());
        let spooled = Arc::new(CompletionRecorder::default());
        let spool = Arc::new(SpoolingExporter::new(
            Arc::clone(&spooled),
            SpoolPolicy::default(),
        ));
        let fanout = FanOutExporter::new(vec![
            Box::new(Arc::clone(&direct)),
            Box::new(Arc::clone(&spool)),
        ]);
        let report = CaptureCompletionReport::new(
            CaptureSourcesReport::new(
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
            ),
            CaptureEventDelivery {
                observed: 2,
                spooled: 1,
                landed: 1,
                rejected: 1,
                ..CaptureEventDelivery::default()
            },
            None,
            None,
            Some("fixture rejection".to_owned()),
        )
        .expect("completion");
        let event = report.to_event(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 2,
                logical: 0,
            },
        );

        fanout
            .export_completion(&event, &report)
            .await
            .expect("fanout completion");
        assert!(spooled.records.lock().expect("spooled records").is_empty());
        assert!(
            spool
                .drain(&crate::blob_drain::DrainRetryPolicy::default())
                .await
                .is_clean()
        );

        assert_eq!(
            *direct.records.lock().expect("direct records"),
            *spooled.records.lock().expect("spooled records")
        );
    }

    #[tokio::test]
    async fn fanout_attempts_every_sink_after_a_sibling_rejects() {
        let recorder = Arc::new(CompletionRecorder::default());
        let memory = Arc::new(MemoryExporter::default());
        let fanout = FanOutExporter::new(vec![
            Box::new(RejectingExporter),
            Box::new(Arc::clone(&memory)),
        ]);
        let event = sample_log_event();

        let error = fanout
            .export(std::slice::from_ref(&event))
            .await
            .expect_err("first sink rejection is returned");
        assert!(matches!(error, ExportError::Rejected { .. }));
        let delivered = memory.events();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].name.as_str(), event.name.as_str());

        let report = CaptureCompletionReport::new(
            CaptureSourcesReport::new(
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::attached_no_data(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::PlatformObserved),
                CaptureSourceReport::off_by_policy(CaptureEvidenceTrust::WorkloadReported),
            ),
            CaptureEventDelivery::default(),
            None,
            None,
            None,
        )
        .expect("completion");
        let completion = report.to_event(
            &RunContext::new_local_root(),
            Hlc {
                wall_ns: 3,
                logical: 0,
            },
        );
        let completion_fanout = FanOutExporter::new(vec![
            Box::new(RejectingExporter),
            Box::new(Arc::clone(&recorder)),
        ]);

        completion_fanout
            .export_completion(&completion, &report)
            .await
            .expect_err("first completion rejection is returned");
        assert_eq!(recorder.records.lock().expect("records").len(), 1);
    }
}
