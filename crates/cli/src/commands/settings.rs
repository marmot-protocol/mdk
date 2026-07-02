//! `settings` command namespace handler, persistence, and the on-disk model.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{CommandOutput, DmError, SettingsCommand, write_private_file};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CliSettings {
    theme: String,
    language: String,
}

impl Default for CliSettings {
    fn default() -> Self {
        Self {
            theme: "system".to_owned(),
            language: "system".to_owned(),
        }
    }
}

pub(crate) fn settings_command(
    home: &Path,
    command: SettingsCommand,
) -> Result<CommandOutput, DmError> {
    let mut settings = read_settings(home)?;
    match command {
        SettingsCommand::Show => {}
        SettingsCommand::Theme { mode } => {
            settings.theme = mode;
            write_settings(home, &settings)?;
        }
        SettingsCommand::Language { lang } => {
            settings.language = lang;
            write_settings(home, &settings)?;
        }
    }
    Ok(CommandOutput {
        plain: format!("theme={} language={}", settings.theme, settings.language),
        json: json!({
            "theme": settings.theme,
            "language": settings.language,
        }),
    })
}

fn settings_path(home: &Path) -> PathBuf {
    home.join("dev").join("settings.json")
}

fn read_settings(home: &Path) -> Result<CliSettings, DmError> {
    let path = settings_path(home);
    if !path.exists() {
        return Ok(CliSettings::default());
    }
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_settings(home: &Path, settings: &CliSettings) -> Result<(), DmError> {
    let path = settings_path(home);
    let bytes = serde_json::to_vec_pretty(settings)?;
    write_private_file(&path, bytes)?;
    Ok(())
}
