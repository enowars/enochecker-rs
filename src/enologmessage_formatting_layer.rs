use std::io::Write;

use serde::ser::{SerializeMap, Serializer as _};
use serde_json::Serializer;
// use crate::storage_layer::JsonStorage;
use time;
use tracing::{Event, Subscriber};
use tracing_serde::AsSerde;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

fn numeric_level(level: &tracing::Level) -> u32 {
    match *level {
        tracing::Level::ERROR => 4,
        tracing::Level::WARN => 3,
        tracing::Level::INFO => 2,
        tracing::Level::DEBUG => 1,
        tracing::Level::TRACE => 0,
    }
}

const MESSAGE_TYPE: &str = "infrastructure";

pub struct EnoLogmessageFormat {
    pub tool: &'static str,
    pub service_name: &'static str,
    pub flatten_event: bool,
}

impl<S, N> FormatEvent<S, N> for EnoLogmessageFormat
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::from("Timestamp Error!"));

        let meta = event.metadata();

        let mut logmessage = Vec::new();
        write!(&mut logmessage, "##ENOLOGMESSAGE ").map_err(|_| std::fmt::Error)?;

        let mut visit = || {
            let mut serializer = Serializer::new(&mut logmessage);

            let mut serializer = serializer.serialize_map(None)?;
            serializer.serialize_entry("timestamp", &timestamp)?;
            serializer.serialize_entry("type", MESSAGE_TYPE)?;
            serializer.serialize_entry("severity", &meta.level().as_serde())?;
            serializer.serialize_entry("severity_level", &numeric_level(meta.level()))?;

            let format_field_marker: std::marker::PhantomData<N> = std::marker::PhantomData;

            let current_span = event
                .parent()
                .and_then(|id| ctx.span(id))
                .or_else(|| ctx.lookup_current());

            if self.flatten_event {
                let mut visitor = tracing_serde::SerdeMapVisitor::new(serializer);
                event.record(&mut visitor);
                serializer = visitor.take_serializer()?;
            } else {
                use tracing_serde::fields::AsMap;
                serializer.serialize_entry("fields", &event.field_map())?;
            };

            serializer.serialize_entry("tool", &self.tool)?;
            serializer.serialize_entry("service_name", &self.service_name)?;

            serializer.serialize_entry("function", meta.target())?;
            if let Some(filename) = meta.file() {
                serializer.serialize_entry("filename", filename)?;
            }

            if let Some(line_number) = meta.line() {
                serializer.serialize_entry("line_number", &line_number)?;
            }

            if let Some(ref span) = current_span {
                serializer
                    .serialize_entry("span", &SerializableSpan(span, format_field_marker))
                    .unwrap_or(());
            }

            serializer.serialize_entry("spans", &SerializableContext(&ctx, format_field_marker))?;

            serializer.end()
        };

        visit().map_err(|_| std::fmt::Error)?;
        writeln!(writer)
    }
}

struct SerializableContext<'a, 'b, Span, N>(
    &'b tracing_subscriber::fmt::FmtContext<'a, Span, N>,
    std::marker::PhantomData<N>,
)
where
    Span: Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static;

impl<'a, 'b, Span, N> serde::ser::Serialize for SerializableContext<'a, 'b, Span, N>
where
    Span: Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn serialize<Ser>(&self, serializer_o: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::ser::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut serializer = serializer_o.serialize_seq(None)?;

        if let Some(leaf_span) = self.0.lookup_current() {
            for span in leaf_span.scope().from_root() {
                serializer.serialize_element(&SerializableSpan(&span, self.1))?;
            }
        }

        serializer.end()
    }
}

struct SerializableSpan<'a, 'b, Span, N>(
    &'b tracing_subscriber::registry::SpanRef<'a, Span>,
    std::marker::PhantomData<N>,
)
where
    Span: for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static;

impl<'a, 'b, Span, N> serde::ser::Serialize for SerializableSpan<'a, 'b, Span, N>
where
    Span: for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::ser::Serializer,
    {
        let mut serializer = serializer.serialize_map(None)?;

        let ext = self.0.extensions();
        let data = ext
            .get::<tracing_subscriber::fmt::FormattedFields<N>>()
            .expect("Unable to find FormattedFields in extensions; this is a bug");

        // TODO: let's _not_ do this, but this resolves
        // https://github.com/tokio-rs/tracing/issues/391.
        // We should probably rework this to use a `serde_json::Value` or something
        // similar in a JSON-specific layer, but I'd (david)
        // rather have a uglier fix now rather than shipping broken JSON.
        match serde_json::from_str::<serde_json::Value>(data) {
            Ok(serde_json::Value::Object(fields)) => {
                for field in fields {
                    serializer.serialize_entry(&field.0, &field.1)?;
                }
            }
            // We have fields for this span which are valid JSON but not an object.
            // This is probably a bug, so panic if we're in debug mode
            Ok(_) if cfg!(debug_assertions) => panic!(
                "span '{}' had malformed fields! this is a bug.\n  error: invalid JSON object\n  fields: {:?}",
                self.0.metadata().name(),
                data
            ),
            // If we *aren't* in debug mode, it's probably best not to
            // crash the program, let's log the field found but also an
            // message saying it's type  is invalid
            Ok(value) => {
                serializer.serialize_entry("field", &value)?;
                serializer.serialize_entry("field_error", "field was no a valid object")?
            }
            // We have previously recorded fields for this span
            // should be valid JSON. However, they appear to *not*
            // be valid JSON. This is almost certainly a bug, so
            // panic if we're in debug mode
            Err(e) if cfg!(debug_assertions) => panic!(
                "span '{}' had malformed fields! this is a bug.\n  error: {}\n  fields: {:?}",
                self.0.metadata().name(),
                e,
                data
            ),
            // If we *aren't* in debug mode, it's probably best not
            // crash the program, but let's at least make sure it's clear
            // that the fields are not supposed to be missing.
            Err(e) => serializer.serialize_entry("field_error", &format!("{}", e))?,
        };
        serializer.serialize_entry("name", self.0.metadata().name())?;
        serializer.end()
    }
}
