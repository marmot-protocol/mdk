use std::collections::BTreeMap;

use crate::{HarnessError, Result};

/// Operator-configured model selection. Values are backend model ids, not prompts.
#[derive(Clone, Default)]
pub struct ModelSelection {
    default: Option<String>,
    aliases: BTreeMap<String, String>,
}

impl ModelSelection {
    /// Validates the default and an optional JSON object of alias-to-model mappings.
    pub fn from_config(default: Option<String>, aliases_json: Option<&str>) -> Result<Self> {
        let aliases: BTreeMap<String, String> = aliases_json
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| HarnessError::Config("invalid model aliases JSON object".to_owned()))?
            .unwrap_or_default();
        if aliases.len() > 128
            || aliases.iter().any(|(alias, model)| {
                !valid_alias(alias) || alias == "default" || !valid_model(model)
            })
            || default.as_deref().is_some_and(|model| !valid_model(model))
        {
            return Err(HarnessError::Config(
                "invalid model selection configuration".to_owned(),
            ));
        }
        Ok(Self { default, aliases })
    }

    /// Returns the configured default; `None` inherits the backend's configuration.
    pub fn default_model(&self) -> Option<&str> {
        self.default.as_deref()
    }

    /// Resolves an alias or a fully qualified model id, failing closed for unknown aliases.
    pub fn resolve(&self, value: &str) -> Option<String> {
        self.aliases
            .get(value)
            .cloned()
            .or_else(|| valid_model(value).then(|| value.to_owned()))
    }

    pub(crate) fn describe(&self, selected: Option<&str>) -> String {
        let model = selected
            .or(self.default_model())
            .unwrap_or("backend default");
        let mut text = format!(
            "Model: {model}\nUse `/model <alias|provider/model#variant>` or `/model default`. The existing session is retained."
        );
        if !self.aliases.is_empty() {
            text.push_str("\nConfigured aliases:");
            for (alias, model) in &self.aliases {
                text.push_str(&format!("\n  {alias} = {model}"));
            }
        }
        text
    }
}

fn valid_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

/// OpenCode's provider/model[#variant] shape, with bounded, control-free argv values.
fn valid_model(value: &str) -> bool {
    if value.len() > 512
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-/:#".contains(&c))
    {
        return false;
    }
    let (base, variant) = value
        .split_once('#')
        .map_or((value, None), |(b, v)| (b, Some(v)));
    let Some((provider, model)) = base.split_once('/') else {
        return false;
    };
    valid_alias(provider)
        && !model.is_empty()
        && !model.starts_with('-')
        && variant.is_none_or(valid_alias)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_resolve_without_changing_backend_configuration() {
        let models =
            ModelSelection::from_config(None, Some(r#"{"deepseek":"venice/deepseek-v4-1-flash"}"#))
                .unwrap();
        assert_eq!(
            models.resolve("deepseek").as_deref(),
            Some("venice/deepseek-v4-1-flash")
        );
        assert_eq!(
            models.resolve("venice/openai-gpt-61-sol#high").as_deref(),
            Some("venice/openai-gpt-61-sol#high")
        );
        assert_eq!(models.resolve("unknown"), None);
        assert_eq!(models.default_model(), None);
    }

    #[test]
    fn invalid_values_fail_without_echoing_configuration() {
        for value in [
            "--model",
            "venice/",
            "/model",
            "venice/model\nsecret",
            "venice/model#",
            "venice/model#high#low",
        ] {
            assert!(ModelSelection::from_config(Some(value.to_owned()), None).is_err());
        }
        for aliases in [
            r#"{"default":"venice/model"}"#,
            r#"{"bad alias":"venice/model"}"#,
            r#"{"alias":"secret"}"#,
            "[]",
        ] {
            let error = ModelSelection::from_config(None, Some(aliases))
                .err()
                .unwrap();
            assert!(!error.to_string().contains("secret"));
        }
    }
}
