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
    let path = &rest[..end];
    if path.is_empty() {
        return None;
    }
    for segment in path.split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return None;
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return None;
        }
    }

    Some((path.to_owned(), rest[end..].trim_start().to_owned()))
}

pub(crate) async fn resolve_repo(name: &str, home: &Path) -> Result<PathBuf> {
    let candidate = home.join(name);
    let canonical = tokio::fs::canonicalize(&candidate)
        .await
        .map_err(|_| repo_error(format!("Directory ~/{name} does not exist.")))?;
    let home_canonical = tokio::fs::canonicalize(home)
        .await
        .map_err(|_| repo_error("Cannot read $HOME."))?;
    if canonical == home_canonical || !canonical.starts_with(&home_canonical) {
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

pub(crate) async fn validate_session_cwd(cwd: &Path, home: &Path) -> Result<PathBuf> {
    let canonical = tokio::fs::canonicalize(cwd)
        .await
        .map_err(|_| repo_error("Stored session workdir cannot be read."))?;
    let home_canonical = tokio::fs::canonicalize(home)
        .await
        .map_err(|_| repo_error("Cannot read $HOME."))?;
    if !canonical.starts_with(&home_canonical) {
        return Err(repo_error(
            "Stored session workdir resolves outside $HOME; refusing.",
        ));
    }
    let metadata = tokio::fs::metadata(&canonical)
        .await
        .map_err(|_| repo_error("Stored session workdir cannot be read."))?;
    if !metadata.is_dir() {
        return Err(repo_error("Stored session workdir is not a directory."));
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
    fn parse_repo_picker_matches_nested_path() {
        assert_eq!(
            parse_repo_picker("/projects/mdk"),
            Some(("projects/mdk".to_owned(), String::new()))
        );
        assert_eq!(
            parse_repo_picker("/projects/mdk fix the build"),
            Some(("projects/mdk".to_owned(), "fix the build".to_owned()))
        );
    }

    #[test]
    fn parse_repo_picker_rejects_bare_slash_or_empty_segments() {
        assert_eq!(parse_repo_picker("/"), None);
        assert_eq!(parse_repo_picker("//whitenoise"), None);
        assert_eq!(parse_repo_picker("/whitenoise/"), None);
        assert_eq!(parse_repo_picker("/whitenoise//subdir"), None);
    }

    #[test]
    fn parse_repo_picker_rejects_dot_segments() {
        assert_eq!(parse_repo_picker("/."), None);
        assert_eq!(parse_repo_picker("/.."), None);
        assert_eq!(parse_repo_picker("/projects/.."), None);
        assert_eq!(parse_repo_picker("/projects/./mdk"), None);
        assert_eq!(parse_repo_picker("/../etc"), None);
    }

    #[test]
    fn parse_repo_picker_ignores_non_picker_text() {
        assert_eq!(parse_repo_picker("hello"), None);
        assert_eq!(parse_repo_picker(" hello"), None);
    }

    #[tokio::test]
    async fn validate_session_cwd_allows_home_or_nested_child() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("repo");
        let nested = child.join("crates").join("engine");
        std::fs::create_dir_all(&nested).unwrap();

        assert_eq!(
            validate_session_cwd(dir.path(), dir.path()).await.unwrap(),
            dir.path().canonicalize().unwrap()
        );
        assert_eq!(
            validate_session_cwd(&child, dir.path()).await.unwrap(),
            child.canonicalize().unwrap()
        );
        assert_eq!(
            validate_session_cwd(&nested, dir.path()).await.unwrap(),
            nested.canonicalize().unwrap()
        );
    }

    #[tokio::test]
    async fn validate_session_cwd_rejects_outside_home() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let err = validate_session_cwd(outside.path(), home.path())
            .await
            .unwrap_err();
        assert_eq!(err.privacy_safe_kind(), "config");
    }

    #[tokio::test]
    async fn resolve_repo_accepts_nested_path() {
        let home = tempfile::tempdir().unwrap();
        let nested = home.path().join("projects").join("mdk");
        std::fs::create_dir_all(&nested).unwrap();

        let resolved = resolve_repo("projects/mdk", home.path()).await.unwrap();
        assert_eq!(resolved, nested.canonicalize().unwrap());
    }

    #[tokio::test]
    async fn resolve_repo_rejects_direct_home_target() {
        let home = tempfile::tempdir().unwrap();
        let err = resolve_repo(".", home.path()).await.unwrap_err();
        assert_eq!(err.privacy_safe_kind(), "config");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn resolve_repo_rejects_symlink_escaping_home() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join("escape")).unwrap();

        let err = resolve_repo("escape", home.path()).await.unwrap_err();
        assert_eq!(err.privacy_safe_kind(), "config");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn validate_session_cwd_rejects_symlink_escaping_home() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let link = home.path().join("escape");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();

        let err = validate_session_cwd(&link, home.path()).await.unwrap_err();
        assert_eq!(err.privacy_safe_kind(), "config");
    }
}
