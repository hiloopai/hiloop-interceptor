//! Wrapper extension contracts for `hiloop-interceptor`.

pub mod blob;
pub mod exporters;
pub mod framing;
pub mod grpc_export;
pub mod inspect;
pub mod jsonl;
pub mod otlp;
pub mod pipeline;
pub mod proxy;
pub mod raw;
pub mod redact;
pub mod seams;
pub mod stdio;
pub mod supervisor;

pub use proxy::DEFAULT_MAX_CAPTURE_BYTES;
pub use redact::RedactionPolicy;
pub use supervisor::{GrpcExportOptions, RunOptions, run};
