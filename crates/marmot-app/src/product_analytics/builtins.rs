use super::*;
fn choice(name: &str, values: &[&str]) -> ProductPropertySchema {
    ProductPropertySchema {
        name: name.into(),
        rule: ProductPropertyRule::Enum(values.iter().map(|v| (*v).into()).collect()),
    }
}
/// Approved host observations provided by MDK. These schemas cannot be overridden.
pub fn approved_host_product_schemas() -> Vec<ProductEventSchema> {
    vec![
        ProductEventSchema {
            name: "app_screen_viewed".into(),
            mode: ProductEventMode::Journey,
            properties: vec![choice(
                "screen",
                &[
                    "onboarding",
                    "inbox",
                    "conversation",
                    "directory",
                    "compose",
                    "group_details",
                    "settings",
                    "diagnostics",
                    "agent",
                ],
            )],
        },
        ProductEventSchema {
            name: "mdk_onboarding_step".into(),
            mode: ProductEventMode::Journey,
            properties: vec![
                choice(
                    "step",
                    &[
                        "start",
                        "identity_selection",
                        "local_ready",
                        "network_ready",
                        "complete",
                    ],
                ),
                choice("path", &["create", "import", "external_signer"]),
                choice("outcome", &["success", "failure", "pending", "cancelled"]),
            ],
        },
        ProductEventSchema {
            name: "mdk_runtime_ready".into(),
            mode: ProductEventMode::Journey,
            properties: vec![
                choice("outcome", &["success", "failure"]),
                ProductPropertySchema {
                    name: "duration_bucket".into(),
                    rule: ProductPropertyRule::DurationBucket,
                },
            ],
        },
        ProductEventSchema {
            name: "app_compose".into(),
            mode: ProductEventMode::Aggregate,
            properties: vec![choice("action", &["open", "cancel"])],
        },
        ProductEventSchema {
            name: "app_message_search".into(),
            mode: ProductEventMode::Aggregate,
            properties: vec![choice(
                "outcome",
                &["success", "empty", "failure", "cancelled"],
            )],
        },
        ProductEventSchema {
            name: "app_attachment".into(),
            mode: ProductEventMode::Aggregate,
            properties: vec![
                choice("action", &["picker", "open", "save"]),
                choice("outcome", &["success", "failure", "cancelled"]),
            ],
        },
        ProductEventSchema {
            name: "app_settings".into(),
            mode: ProductEventMode::Aggregate,
            properties: vec![choice(
                "section",
                &[
                    "appearance",
                    "notifications",
                    "privacy",
                    "account",
                    "storage",
                    "diagnostics",
                ],
            )],
        },
        ProductEventSchema {
            name: "app_notification_permission".into(),
            mode: ProductEventMode::Aggregate,
            properties: vec![choice(
                "outcome",
                &["granted", "denied", "restricted", "provisional"],
            )],
        },
    ]
}
