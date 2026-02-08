use std::sync::{Arc, OnceLock};
use tracing::{Subscriber, Event};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

// Define the Logger trait that matches the UDL interface
pub trait CoreLogger: Send + Sync {
    fn log(&self, level: String, message: String);
}

// Global storage for the logger callback
static GLOBAL_LOGGER: OnceLock<Arc<dyn CoreLogger>> = OnceLock::new();

pub struct UniFFILogger;

impl<S> Layer<S> for UniFFILogger
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if let Some(logger) = GLOBAL_LOGGER.get() {
            let level = event.metadata().level().to_string();
            let mut message = String::new();
            let mut visitor = MessageVisitor(&mut message);
            event.record(&mut visitor);
            logger.log(level, message);
        }
    }
}

struct MessageVisitor<'a>(&'a mut String);

impl<'a> tracing::field::Visit for MessageVisitor<'a> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write;
            let _ = write!(self.0, "{:?}", value);
        }
    }
}

pub fn init_logger(callback: Box<dyn CoreLogger>) {
    if GLOBAL_LOGGER.set(Arc::from(callback)).is_err() {
        // value already set
        return;
    }
    
    // Set up tracing subscriber
    let subscriber = tracing_subscriber::registry()
        .with(UniFFILogger)
        .with(tracing_subscriber::filter::LevelFilter::DEBUG);
        
    let _ = tracing::subscriber::set_global_default(subscriber);
}
