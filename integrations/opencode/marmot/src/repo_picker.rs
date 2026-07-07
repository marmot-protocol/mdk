use std::path::{Path, PathBuf};

use crate::error::{HarnessError, Result};

pub(crate) fn parse_repo_picker(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with('/') {
        return None;
    }

    let rest = &trimmed[1..];
    let end = rest
        .char_indices()
        .find(|(_, c)| c.is_whitespace())
        .map(|(index, _)| index)
        .unwrap_or(rest.len());
    let name = &rest[..end];
    if name.is_empty() || matches!(name, "." | "..") {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return None;
    }

    Some((name.to_owned(), rest[end..].trim_start().to_owned()))
}

pub(crate) async fn resolve_repo(name: &str, home: &Path) -> Result<PathBuf> {
    let candidate = home.join(name);
    let canonical = tokio::fs::canonicalize(&candidate)
        .await
        .map_err(|_| repo_error(format!("Directory ~/{name} does not exist.")))?;
    let home_canonical = tokio::fs::canonicalize(home)
        .await
        .map_err(|_| repo_error("Cannot read $HOME."))?;
    if canonical.parent() != Some(&home_canonical) {
        return Err(repo_error(format!(
            "Repo ~/{name} resolves outside $HOME; refusing."
        )));
    }
    let metadata = tokio::fs::metadata(&canonical)
        .await
        .map_err(|_| repo_error(format!("Cannot read ~/{name}.")))?;
    if !metadata.is_dir() {
        return Err(repo_error(format!("~/{name} is not a directory.")));
    }
    Ok(canonical)
}

fn repo_error(message: impl Into<String>) -> HarnessError {
    HarnessError::Config(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_repo_picker_matches_bare_name() {
        assert_eq!(
            parse_repo_picker("/whitenoise"),
            Some(("whitenoise".to_owned(), String::new()))
        );
    }

    #[test]
    fn parse_repo_picker_matches_name_with_rest() {
        assert_eq!(
            parse_repo_picker("/whitenoise fix the build"),
            Some(("whitenoise".to_owned(), "fix the build".to_owned()))
        );
    }

    #[test]
    fn parse_repo_picker_rejects_bare_slash_or_path_segments() {
        assert_eq!(parse_repo_picker("/"), None);
        assert_eq!(parse_repo_picker("/whitenoise/subdir"), None);
    }

    #[test]
    fn parse_repo_picker_rejects_dot_segments() {
        assert_eq!(parse_repo_picker("/."), None);
        assert_eq!(parse_repo_picker("/.."), None);
    }

    #[test]
    fn parse_repo_picker_ignores_non_picker_text() {
        assert_eq!(parse_repo_picker("hello"), None);
        assert_eq!(parse_repo_picker(" hello"), None);
    }
}
