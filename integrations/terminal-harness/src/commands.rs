use crate::repo_picker::is_valid_relative_path;

/// Maximum byte length of a stored standing goal.
pub(crate) const MAX_GOAL_BYTES: usize = 4096;

/// One reserved harness chat command.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChatCommand {
    /// List the reserved commands and the workdir picker.
    Help,
    /// Report this lane's workdir, session, goal, and execution profile.
    Status,
    /// Report this lane's working directory.
    Pwd,
    /// Select a working directory and start a new session epoch.
    Cd { path: String },
    /// End the active backend session while retaining the workdir.
    NewSession,
    /// Retry the durable recovery record owned by PR #1568.
    RetryLast,
    /// Discard the durable recovery record owned by PR #1568.
    DiscardLast,
    /// Report the stored standing goal.
    GoalShow,
    /// Remove the stored standing goal.
    GoalClear,
    /// Replace the stored standing goal.
    GoalSet { text: String },
}

/// How one inbound message body is routed before backend invocation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Routed {
    /// A reserved harness command with usable arguments.
    Command(ChatCommand),
    /// A reserved command name used with unusable arguments.
    Usage(&'static str),
    /// Text forwarded verbatim; the workdir picker never applies.
    Literal(String),
    /// Ordinary prompt text; the workdir picker still applies.
    Prompt(String),
}

/// Reserved command names paired with their `/help` description.
const RESERVED: &[(&str, &str)] = &[
    ("help", "list these commands"),
    ("status", "show this chat's workdir, session, and goal"),
    ("pwd", "show this chat's working directory"),
    (
        "cd",
        "`/cd <path>` selects a working directory under $HOME and starts a new session",
    ),
    (
        "new",
        "end the current backend session and keep the workdir",
    ),
    ("reset-session", "same as `/new`"),
    (
        "session-status",
        "show active-turn lane status when that lane is supported",
    ),
    ("retry-last", "retry the last recoverable backend attempt"),
    (
        "discard-last",
        "discard the last recoverable backend attempt",
    ),
    (
        "goal",
        "`/goal <text>` sets a standing instruction, `/goal` shows it, `/goal clear` removes it",
    ),
];

/// Returns true when `name` is a reserved harness command name.
#[cfg(test)]
fn is_reserved(name: &str) -> bool {
    RESERVED.iter().any(|(reserved, _)| *reserved == name)
}

/// Renders the `/help` body for one connector.
pub(crate) fn help_text(display_name: &str) -> String {
    let mut text = format!("Commands handled by the harness, not by {display_name}:\n");
    for (name, description) in RESERVED {
        text.push_str(&format!("  /{name} - {description}\n"));
    }
    text.push_str(
        "\nAnything else is sent to the backend as a prompt. On a chat with no workdir yet, `/<path>` \
         selects a working directory under $HOME and the rest of the message becomes the first prompt. \
         Prefix a message with `//` to send a literal leading slash, for example `//status`. A directory \
         whose name matches a reserved command must be selected with `/cd`.",
    );
    text
}

/// Routes one inbound message body.
pub(crate) fn route(text: &str) -> Routed {
    let trimmed = text.trim();
    let Some(rest) = trimmed.strip_prefix('/') else {
        return Routed::Prompt(text.to_owned());
    };
    if rest.starts_with('/') {
        let leading_bytes = text.len() - text.trim_start().len();
        let escaped = &text[leading_bytes + 1..];
        return Routed::Literal(format!("{}{escaped}", &text[..leading_bytes]));
    }

    let (name, args) = split_command(rest);
    match name {
        "help" => bare(ChatCommand::Help, args, "`/help` takes no arguments."),
        "status" => bare(ChatCommand::Status, args, "`/status` takes no arguments."),
        "pwd" => bare(ChatCommand::Pwd, args, "`/pwd` takes no arguments."),
        "new" => bare(ChatCommand::NewSession, args, "`/new` takes no arguments."),
        "reset-session" => bare(
            ChatCommand::NewSession,
            args,
            "`/reset-session` takes no arguments.",
        ),
        "session-status" => Routed::Usage(
            "`/session-status` is reserved for active-turn lane status and is not available in this harness yet.",
        ),
        "retry-last" => bare(
            ChatCommand::RetryLast,
            args,
            "`/retry-last` takes no arguments.",
        ),
        "discard-last" => bare(
            ChatCommand::DiscardLast,
            args,
            "`/discard-last` takes no arguments.",
        ),
        "cd" => route_cd(args),
        "goal" => route_goal(args),
        _ => Routed::Prompt(text.to_owned()),
    }
}

fn route_cd(args: &str) -> Routed {
    const USAGE: &str =
        "Use `/cd <path>` with one path under $HOME, for example `/cd projects/mdk`.";
    let path = args.trim();
    if path.is_empty() || path.split_whitespace().count() != 1 || !is_valid_relative_path(path) {
        return Routed::Usage(USAGE);
    }
    Routed::Command(ChatCommand::Cd {
        path: path.to_owned(),
    })
}

fn route_goal(args: &str) -> Routed {
    let text = args.trim();
    if text.is_empty() {
        return Routed::Command(ChatCommand::GoalShow);
    }
    if text == "clear" {
        return Routed::Command(ChatCommand::GoalClear);
    }
    if text.len() > MAX_GOAL_BYTES {
        return Routed::Usage("The goal is too long. Keep it under 4096 bytes.");
    }
    Routed::Command(ChatCommand::GoalSet {
        text: text.to_owned(),
    })
}

fn bare(command: ChatCommand, args: &str, usage: &'static str) -> Routed {
    if args.trim().is_empty() {
        Routed::Command(command)
    } else {
        Routed::Usage(usage)
    }
}

fn split_command(rest: &str) -> (&str, &str) {
    match rest.find(char::is_whitespace) {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    }
}

/// Prepends the stored standing goal to one prompt.
pub(crate) fn apply_goal(goal: &str, prompt: &str) -> String {
    format!(
        "Standing goal for this chat, set by the user and applied to every prompt:\n{goal}\n\n---\n\n{prompt}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_reserved_names_never_route_to_the_backend() {
        assert_eq!(route("/help"), Routed::Command(ChatCommand::Help));
        assert_eq!(route("  /status\n"), Routed::Command(ChatCommand::Status));
        assert_eq!(route("/pwd"), Routed::Command(ChatCommand::Pwd));
        assert_eq!(route("/new"), Routed::Command(ChatCommand::NewSession));
        assert_eq!(
            route("/reset-session"),
            Routed::Command(ChatCommand::NewSession)
        );
        assert!(matches!(route("/session-status"), Routed::Usage(_)));
        assert_eq!(
            route("/retry-last"),
            Routed::Command(ChatCommand::RetryLast)
        );
        assert_eq!(
            route("/discard-last"),
            Routed::Command(ChatCommand::DiscardLast)
        );
    }

    #[test]
    fn reserved_names_with_stray_arguments_report_usage_instead_of_prompting() {
        assert_eq!(
            route("/reset-session please"),
            Routed::Usage("`/reset-session` takes no arguments.")
        );
        assert_eq!(
            route("/new now"),
            Routed::Usage("`/new` takes no arguments.")
        );
        assert_eq!(
            route("/help me"),
            Routed::Usage("`/help` takes no arguments.")
        );
    }

    #[test]
    fn double_slash_forwards_one_literal_slash_and_skips_the_picker() {
        assert_eq!(
            route("//reset-session"),
            Routed::Literal("/reset-session".to_owned())
        );
        assert_eq!(route("//status"), Routed::Literal("/status".to_owned()));
        assert_eq!(
            route("//usr/bin/env is a path"),
            Routed::Literal("/usr/bin/env is a path".to_owned())
        );
        assert_eq!(
            route("  //status \n"),
            Routed::Literal("  /status \n".to_owned())
        );
    }

    #[test]
    fn unreserved_leading_slash_stays_a_prompt_so_the_picker_still_applies() {
        assert_eq!(
            route("/whitenoise fix the build"),
            Routed::Prompt("/whitenoise fix the build".to_owned())
        );
        assert_eq!(
            route("/projects/mdk"),
            Routed::Prompt("/projects/mdk".to_owned())
        );
    }

    #[test]
    fn plain_text_is_never_a_command() {
        assert_eq!(route("hello"), Routed::Prompt("hello".to_owned()));
        assert_eq!(
            route("run /help for me"),
            Routed::Prompt("run /help for me".to_owned())
        );
    }

    #[test]
    fn prompt_routing_preserves_the_original_bytes() {
        assert_eq!(
            route("  keep   my\n whitespace  "),
            Routed::Prompt("  keep   my\n whitespace  ".to_owned())
        );
    }

    #[test]
    fn cd_requires_exactly_one_valid_relative_path() {
        assert_eq!(
            route("/cd projects/mdk"),
            Routed::Command(ChatCommand::Cd {
                path: "projects/mdk".to_owned()
            })
        );
        for rejected in [
            "/cd",
            "/cd ",
            "/cd a b",
            "/cd ..",
            "/cd projects/../etc",
            "/cd /absolute",
            "/cd projects/",
            "/cd proj!ect",
        ] {
            assert!(
                matches!(route(rejected), Routed::Usage(_)),
                "expected usage error for {rejected}"
            );
        }
    }

    #[test]
    fn goal_supports_show_set_and_clear() {
        assert_eq!(route("/goal"), Routed::Command(ChatCommand::GoalShow));
        assert_eq!(route("/goal   "), Routed::Command(ChatCommand::GoalShow));
        assert_eq!(
            route("/goal clear"),
            Routed::Command(ChatCommand::GoalClear)
        );
        assert_eq!(
            route("/goal ship the connector"),
            Routed::Command(ChatCommand::GoalSet {
                text: "ship the connector".to_owned()
            })
        );
    }

    #[test]
    fn goal_rejects_bodies_over_the_stored_bound() {
        let long = "g".repeat(MAX_GOAL_BYTES + 1);
        assert!(matches!(route(&format!("/goal {long}")), Routed::Usage(_)));
        let limit = "g".repeat(MAX_GOAL_BYTES);
        assert_eq!(
            route(&format!("/goal {limit}")),
            Routed::Command(ChatCommand::GoalSet { text: limit })
        );
    }

    #[test]
    fn help_lists_every_reserved_command() {
        let text = help_text("codex");
        for (name, _) in RESERVED {
            assert!(text.contains(&format!("/{name} ")), "missing /{name}");
        }
        assert!(text.contains("codex"));
        assert!(text.contains("//"));
    }

    #[test]
    fn every_reserved_name_routes_away_from_the_picker() {
        for (name, _) in RESERVED {
            assert!(is_reserved(name));
            assert!(
                !matches!(route(&format!("/{name}")), Routed::Prompt(_)),
                "/{name} must not fall through to the workdir picker"
            );
        }
        assert!(!is_reserved("whitenoise"));
    }

    #[test]
    fn goal_is_prepended_as_a_delimited_block() {
        let combined = apply_goal("keep CI green", "fix the failing test");
        assert!(combined.starts_with("Standing goal for this chat"));
        assert!(combined.contains("keep CI green"));
        assert!(combined.ends_with("fix the failing test"));
    }
}
