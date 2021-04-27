// use crate::storage_layer::JsonStorage;
use serde::ser::{SerializeMap, Serializer};
use serde_json::Value;

use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use tracing::field::{Field, Visit};
use tracing::{span::Record, Event, Id, Subscriber};
use tracing_core::metadata::Level;
use tracing_core::span::Attributes;
use tracing_subscriber::fmt::time::{ChronoUtc, FormatTime};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::SpanRef;
use tracing_subscriber::Layer;

#[derive(Clone, Debug)]
pub struct EnoLogmessageStorage<'a> {
    values: HashMap<&'a str, serde_json::Value>,
}

impl<'a> EnoLogmessageStorage<'a> {
    /// Get the set of stored values, as a set of keys and JSON values.
    pub fn values(&self) -> &HashMap<&'a str, serde_json::Value> {
        &self.values
    }
}

/// Get a new visitor, with an empty bag of key-value pairs.
impl Default for EnoLogmessageStorage<'_> {
    fn default() -> Self {
        Self {
            values: HashMap::new(),
        }
    }
}

/// Taken verbatim from tracing-subscriber
impl Visit for EnoLogmessageStorage<'_> {
    /// Visit a signed 64-bit integer value.
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.values
            .insert(&field.name(), serde_json::Value::from(value));
    }

    /// Visit an unsigned 64-bit integer value.
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.values
            .insert(&field.name(), serde_json::Value::from(value));
    }

    /// Visit a boolean value.
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.values
            .insert(&field.name(), serde_json::Value::from(value));
    }

    /// Visit a string value.
    fn record_str(&mut self, field: &Field, value: &str) {
        self.values
            .insert(&field.name(), serde_json::Value::from(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        match field.name() {
            // Skip fields that are actually log metadata that have already been handled
            name if name.starts_with("log.") => (),
            name if name.starts_with("r#") => {
                self.values
                    .insert(&name[2..], serde_json::Value::from(format!("{:?}", value)));
            }
            name => {
                self.values
                    .insert(name, serde_json::Value::from(format!("{:?}", value)));
            }
        };
    }
}

const MESSAGE_TYPE: &'static str = "infrastructure";

pub struct EnoLogmessageLayer<W: MakeWriter + 'static> {
    make_writer: W,
    tool: String,
    service_name: &'static str,
    timer: ChronoUtc,
}

impl<W: MakeWriter + 'static> EnoLogmessageLayer<W> {
    /// Create a new `ENOELKFormattingLayer`.

    pub fn new(service_name: &'static str, make_writer: W) -> Self {
        Self {
            make_writer,
            service_name,
            tool: service_name.to_owned() + "Checker",
            timer: ChronoUtc::rfc3339(),
        }
    }

    // fn serialize_bunyan_core_fields(
    //     &self,
    //     map_serializer: &mut impl SerializeMap<Error = serde_json::Error>,
    //     message: &str,
    //     level: &Level,
    // ) -> Result<(), std::io::Error> {
    //     map_serializer.serialize_entry(BUNYAN_VERSION, &self.bunyan_version)?;
    //     map_serializer.serialize_entry(NAME, &self.name)?;
    //     map_serializer.serialize_entry(MESSAGE, &message)?;
    //     map_serializer.serialize_entry(LEVEL, &to_bunyan_level(level))?;
    //     map_serializer.serialize_entry(HOSTNAME, &self.hostname)?;
    //     map_serializer.serialize_entry(PID, &self.pid)?;
    //     map_serializer.serialize_entry(TIME, &chrono::Utc::now().to_rfc3339())?;
    //     Ok(())
    // }

    /// Given a span, it serialised it to a in-memory buffer (vector of bytes).
    // fn serialize_span<S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>>(
    //     &self,
    //     span: &SpanRef<S>,
    //     ty: Type,
    // ) -> Result<Vec<u8>, std::io::Error> {
    //     let mut buffer = Vec::new();
    //     let mut serializer = serde_json::Serializer::new(&mut buffer);
    //     let mut map_serializer = serializer.serialize_map(None)?;
    //     let message = format_span_context(&span, ty);
    //     self.serialize_bunyan_core_fields(&mut map_serializer, &message, span.metadata().level())?;
    //     // Additional metadata useful for debugging
    //     // They should be nested under `src` (see https://github.com/trentm/node-bunyan#src )
    //     // but `tracing` does not support nested values yet
    //     map_serializer.serialize_entry("target", span.metadata().target())?;
    //     map_serializer.serialize_entry("line", &span.metadata().line())?;
    //     map_serializer.serialize_entry("file", &span.metadata().file())?;

    //     let extensions = span.extensions();
    //     if let Some(visitor) = extensions.get::<JsonStorage>() {
    //         for (key, value) in visitor.values() {
    //             map_serializer.serialize_entry(key, value)?;
    //         }
    //     }
    //     map_serializer.end()?;
    //     Ok(buffer)
    // }

    fn emit(&self, buffer: &[u8]) -> Result<(), std::io::Error> {
        let mut writer = self.make_writer.make_writer();

        let mut message = b"##ENOLOGMESSAGE ".to_vec();
        message.write_all(&buffer)?;
        message.write_all(b"\n")?;

        writer.write_all(&message)
    }
}

/// The type of record we are dealing with: entering a span, exiting a span, an event.
#[derive(Clone, Debug)]
pub enum Type {
    EnterSpan,
    ExitSpan,
    Event,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let repr = match self {
            Type::EnterSpan => "START",
            Type::ExitSpan => "END",
            Type::Event => "EVENT",
        };
        write!(f, "{}", repr)
    }
}

/// Ensure consistent formatting of the span context.
///
/// Example: "[AN_INTERESTING_SPAN - START]"
fn format_span_context<S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>>(
    span: &SpanRef<S>,
    ty: Type,
) -> String {
    format!("[{} - {}]", span.metadata().name().to_uppercase(), ty)
}

/// Ensure consistent formatting of event message.
///
/// Examples:
/// - "[AN_INTERESTING_SPAN - EVENT] My event message" (for an event with a parent span)
/// - "My event message" (for an event without a parent span)
fn format_event_message<S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>>(
    current_span: &Option<SpanRef<S>>,
    event: &Event,
    event_visitor: &EnoLogmessageStorage<'_>,
) -> String {
    // Extract the "message" field, if provided. Fallback to the target, if missing.
    let mut message = event_visitor
        .values()
        .get("message")
        .map(|v| match v {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        })
        .flatten()
        .unwrap_or_else(|| event.metadata().target())
        .to_owned();

    // If the event is in the context of a span, prepend the span name to the message.
    if let Some(span) = &current_span {
        message = format!("{} {}", format_span_context(span, Type::Event), message);
    }

    message
}

fn to_camel_case(field: &str) -> String {
    let mut buffer = String::with_capacity(field.len());

    let mut capitalization = false;
    for c in field.chars() {
        if c == '_' {
            capitalization = true;
        } else if capitalization {
            buffer.push(c.to_ascii_uppercase());
            capitalization = false;
        } else {
            buffer.push(c);
        }
    }

    buffer
}

/// Convert from log levels to Bunyan's levels.
fn level_numeric(level: &Level) -> u16 {
    match level {
        &Level::ERROR => 50,
        &Level::WARN => 40,
        &Level::INFO => 30,
        &Level::DEBUG => 20,
        &Level::TRACE => 10,
    }
}

impl<S, W> Layer<S> for EnoLogmessageLayer<W>
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: MakeWriter + 'static,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        // Events do not necessarily happen in the context of a span, hence lookup_current
        // returns an `Option<SpanRef<_>>` instead of a `SpanRef<_>`.
        let current_span = ctx.lookup_current();

        let mut event_visitor = EnoLogmessageStorage::default();
        event.record(&mut event_visitor);

        // Opting for a closure to use the ? operator and get more linear code.
        let format = || {
            let mut buffer = Vec::new();

            let mut serializer = serde_json::Serializer::new(&mut buffer);
            let mut map_serializer = serializer.serialize_map(None)?;

            let message = format_event_message(&current_span, event, &event_visitor);

            // Add constant fields
            map_serializer.serialize_entry("tool", self.tool.as_str())?;
            map_serializer.serialize_entry("type", MESSAGE_TYPE)?;
            map_serializer.serialize_entry("serviceName", self.service_name)?;
            map_serializer.serialize_entry("message", message.as_str())?;

            // Add all the other fields associated with the event, expect the message we already used.
            for (key, value) in event_visitor
                .values()
                .iter()
                .filter(|(&key, _)| key != "message")
            {
                map_serializer.serialize_entry(&to_camel_case(&key), value)?;
            }

            let metadata = event.metadata();
            map_serializer.serialize_entry("module", &metadata.module_path())?;
            if let Some(file) = metadata.file() {
                let function = match metadata.line() {
                    Some(line) => format!("{}:{}", file, line),
                    None => file.to_owned(),
                };

                map_serializer.serialize_entry("function", &function)?;
            }
            map_serializer.serialize_entry("serverity", &metadata.level().to_string())?;
            map_serializer.serialize_entry("severityLevel", &level_numeric(&metadata.level()))?;

            let mut timestamp = String::new();
            self.timer
                .format_time(&mut timestamp)
                .expect("Failed to format time");
            map_serializer.serialize_entry("timestamp", &timestamp)?;

            // Add all the fields from the current span, if we have one.
            if let Some(span) = &current_span {
                let extensions = span.extensions();
                if let Some(visitor) = extensions.get::<EnoLogmessageStorage>() {
                    for (key, value) in visitor.values() {
                        map_serializer.serialize_entry(&to_camel_case(&key), value)?;
                    }
                }
            }
            // eprintln!("{:?}", event);
            map_serializer.end()?;
            Ok(buffer)
        };

        let result: std::io::Result<Vec<u8>> = format();
        if let Ok(formatted) = result {
            let _ = self.emit(&formatted);
        }
    }

    fn on_record(&self, span: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let span = ctx.span(span).expect("Span not found, this is a bug");

        // Before you can associate a record to an existing Span, well, that Span has to be created!
        // We can thus rely on the invariant that we always associate a JsonVisitor with a Span
        // on creation (`new_span` method), hence it's safe to unwrap the Option.
        let mut extensions = span.extensions_mut();
        let visitor = extensions
            .get_mut::<EnoLogmessageStorage>()
            .expect("Visitor not found on 'record', this is a bug");
        // Register all new fields
        values.record(visitor);
    }

    fn new_span(&self, attrs: &Attributes, id: &Id, ctx: Context<'_, S>) {
        // let span = ctx.span(id).expect("Span not found, this is a bug");
        // if let Ok(serialized) = self.serialize_span(&span, Type::EnterSpan) {
        //     let _ = self.emit(serialized);
        // }
        let span = ctx.span(id).expect("Span not found, this is a bug");
        // We want to inherit the fields from the parent span, if there is one.
        let mut visitor = if let Some(parent_span) = span.parent() {
            // Extensions can be used to associate arbitrary data to a span.
            // We'll use it to store our representation of its fields.
            // We create a copy of the parent visitor!
            let mut extensions = parent_span.extensions_mut();
            extensions
                .get_mut::<EnoLogmessageStorage>()
                .map(|v| v.to_owned())
                .unwrap_or_default()
        } else {
            EnoLogmessageStorage::default()
        };

        let mut extensions = span.extensions_mut();

        // Register all fields.
        // Fields on the new span should override fields on the parent span if there is a conflict.
        attrs.record(&mut visitor);
        // Associate the visitor with the Span for future usage via the Span's extensions
        extensions.insert(visitor);

        eprintln!("NEW: {:?}, ID: {:?}", attrs, id);
    }

    /// When we enter a span **for the first time** save the timestamp in its extensions.
    fn on_enter(&self, span: &Id, ctx: Context<'_, S>) {
        // eprintln!("ENTER {:?}", span);
        // TODO: LOG SPAN ENTER?
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        // let span = ctx.span(&id).expect("Span not found, this is a bug");
        // if let Ok(serialized) = self.serialize_span(&span, Type::ExitSpan) {
        //     let _ = self.emit(serialized);
        // }
        // eprintln!("CLOSE: {:?}", id);
    }
}
