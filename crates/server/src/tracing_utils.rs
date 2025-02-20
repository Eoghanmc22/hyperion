#[cfg(all(
    feature = "trace",
    not(feature = "trace-simple"),
    not(feature = "tracy")
))]
fn setup_global_subscriber() -> impl Drop {
    use tracing_flame::FlameLayer;
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    let fmt_layer = fmt::Layer::default();

    let (flame_layer, guard) = FlameLayer::with_file("./tracing.folded").unwrap();

    // Define an environment filter layer
    // This reads the `RUST_LOG` environment variable to set the log level
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info")) // Fallback to "info" level if `RUST_LOG` is not set
        .unwrap();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(flame_layer)
        .init();

    guard
}

#[cfg(all(
    feature = "trace-simple",
    not(feature = "trace"),
    not(feature = "tracy")
))]
fn setup_simple_trace() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info")) // Fallback to "info" level if `RUST_LOG` is not set
        .unwrap();

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .pretty()
        .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new(
            "%H:%M:%S%.3f".to_owned(),
        ))
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .try_init()
        .unwrap();
}

#[cfg(all(
    feature = "tracy",
    not(feature = "trace"),
    not(feature = "trace-simple")
))]
fn setup_tracy() {
    use tracing_subscriber::layer::SubscriberExt;

    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(tracing_tracy::TracyLayer::default()),
    )
    .expect("setup tracy layer");
}

pub fn with_tracing<T>(f: impl FnOnce() -> T) -> T {
    #[cfg(all(
        feature = "trace-simple",
        not(feature = "trace"),
        not(feature = "tracy")
    ))]
    setup_simple_trace();

    #[cfg(all(
        feature = "tracy",
        not(feature = "trace"),
        not(feature = "trace-simple")
    ))]
    setup_tracy();

    #[cfg(all(
        feature = "trace",
        not(feature = "tracy"),
        not(feature = "trace-simple")
    ))]
    let _guard = setup_global_subscriber();

    #[cfg(feature = "pprof")]
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(2999)
        .blocklist(&["libc", "libgcc", "pthread", "vdso", "rayon"])
        .build()
        .unwrap();

    let result = f();

    #[cfg(feature = "pprof")]
    if let Ok(report) = guard.report().build() {
        let file = std::fs::File::create("flamegraph.svg").unwrap();
        report.flamegraph(file).unwrap();
    };

    result
}
