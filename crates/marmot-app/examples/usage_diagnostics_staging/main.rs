//! Synthetic staging check and minimal host integration. Never uses a real account.
#[cfg(feature = "product-analytics-export")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use marmot_app::*;
    if !std::env::args().any(|arg| arg == "--send-synthetic") {
        println!(
            "Pass --send-synthetic with explicit staging endpoint, key, operator and environment variables."
        );
        return Ok(());
    }
    if std::env::var("MARMOT_PRODUCT_ANALYTICS_ENVIRONMENT").as_deref() != Ok("staging") {
        return Err("synthetic check requires an explicit staging environment".into());
    }
    let endpoint = std::env::var("MARMOT_PRODUCT_ANALYTICS_EVENTS_ENDPOINT")
        .map_err(|_| "missing staging events endpoint")?;
    let key =
        std::env::var("MARMOT_PRODUCT_ANALYTICS_APP_KEY").map_err(|_| "missing staging app key")?;
    let operator = std::env::var("MARMOT_PRODUCT_ANALYTICS_OPERATOR")
        .map_err(|_| "missing staging operator")?;
    let home = tempfile::tempdir()?;
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        home.path(),
        Vec::new(),
        marmot_account::AccountHome::open(home.path()),
        MarmotAppConfig::default(),
    )?;
    let runtime = app.runtime();
    runtime.set_product_analytics_runtime_config(ProductAnalyticsRuntimeConfig {
        events_endpoint: Some(endpoint),
        app_key: Some(key),
        operator,
        allow_loopback: std::env::var("MARMOT_PRODUCT_ANALYTICS_ALLOW_LOOPBACK").as_deref()
            == Ok("1"),
        metadata: ProductAnalyticsMetadata {
            app_version: env!("CARGO_PKG_VERSION").into(),
            os_family: std::env::consts::OS.into(),
            os_major_version: String::new(),
            device_class: "headless".into(),
            host_surface: "native".into(),
            environment: "staging".into(),
            is_debug: true,
        },
        registry: vec![],
    })?;
    // This executable's explicit flag grants consent for synthetic, temporary state only.
    // Native apps must present the disclosure and wait for their user's affirmative action.
    runtime.set_usage_diagnostics_consent(true)?;
    runtime
        .set_product_analytics_activity(ProductAnalyticsActivity::Foreground)
        .await;
    runtime.record_product_event(ProductEvent {
        name: "app_screen_viewed".into(),
        properties: [("screen".into(), "diagnostics".into())].into(),
    })?;
    runtime.flush_product_analytics().await;
    let status = runtime.usage_diagnostics_status();
    println!("{}", serde_json::to_string(&status)?);
    runtime.set_usage_diagnostics_consent(false)?;
    runtime.shutdown_and_close().await?;
    if status.accepted_batches == 0 {
        return Err("staging ingestion did not acknowledge the synthetic batch".into());
    }
    // A 2xx proves ingestion admission only. Inspect persistence and enrichment separately.
    Ok(())
}

#[cfg(not(feature = "product-analytics-export"))]
fn main() {
    eprintln!("Build this example with --features product-analytics-export");
}
