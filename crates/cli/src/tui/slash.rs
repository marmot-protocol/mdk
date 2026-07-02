//! Slash-command parsing for the TUI composer.

use super::*;

pub(crate) fn parse_slash_command(input: &str) -> Result<SlashCommand, String> {
    let trimmed = input.trim();
    if !trimmed.starts_with('/') {
        return Err("slash command must start with /".to_owned());
    }
    let mut parts = split_slash_command_words(&trimmed[1..])?;
    if parts.is_empty() {
        return Err("empty slash command".to_owned());
    }
    let command = parts.remove(0);
    let rest = parts;
    match command.as_str() {
        "help" | "?" => Ok(SlashCommand::Help),
        "refresh" => Ok(SlashCommand::Refresh),
        "sync" => {
            Err("manual sync is not a TUI command; live updates come from subscriptions".to_owned())
        }
        "create-identity" => {
            if rest.is_empty() {
                Ok(SlashCommand::AccountCreate)
            } else {
                Err("/create-identity does not accept arguments".to_owned())
            }
        }
        "login" => match rest.as_slice() {
            [identity] if identity.starts_with("nsec") => {
                Ok(SlashCommand::AccountImportSecret(identity.clone()))
            }
            [identity] => Ok(SlashCommand::AccountAddPublic(identity.clone())),
            [] => Err("/login expects one nsec or npub".to_owned()),
            _ => Err("/login expects exactly one nsec or npub".to_owned()),
        },
        "account" => parse_account_command(rest),
        "daemon" => parse_daemon_command(rest),
        "chat" => parse_chat_command(rest),
        "members" => parse_members_command(rest),
        "keys" => parse_keys_command(rest),
        "profile" => parse_profile_command(rest),
        "name" => parse_profile_name_command(rest),
        "stream" => parse_stream_command(rest),
        "quit" | "q" => Ok(SlashCommand::Quit),
        other => Err(format!("unknown slash command: /{other}")),
    }
}

pub(crate) fn slash_command_suggestions(input: &str) -> Vec<&'static SlashCommandSuggestion> {
    if !is_slash_command_input(input) {
        return Vec::new();
    }
    SLASH_COMMAND_SUGGESTIONS
        .iter()
        .filter(|suggestion| slash_suggestion_matches(input, suggestion))
        .collect()
}

pub(crate) fn slash_suggestion_lines(input: &str, limit: usize) -> Vec<Line<'static>> {
    if !is_slash_command_input(input) {
        return Vec::new();
    }

    let suggestions = slash_command_suggestions(input);
    if suggestions.is_empty() {
        return vec![Line::from(Span::styled(
            "no matching commands",
            Style::default().fg(Color::DarkGray),
        ))];
    }

    suggestions
        .into_iter()
        .take(limit)
        .map(|suggestion| {
            Line::from(vec![
                Span::styled(
                    suggestion.usage,
                    Style::default()
                        .fg(FOCUS_ACCENT)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::raw(suggestion.description),
            ])
        })
        .collect()
}

pub(crate) fn is_slash_command_input(input: &str) -> bool {
    input.starts_with('/')
}

pub(crate) fn slash_suggestion_matches(input: &str, suggestion: &SlashCommandSuggestion) -> bool {
    let typed_words = input
        .to_ascii_lowercase()
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if typed_words.is_empty() {
        return true;
    }

    let literal_words = suggestion
        .usage
        .split_whitespace()
        .take_while(|word| !word.starts_with('<') && !word.starts_with('['))
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();

    for (index, typed_word) in typed_words.iter().enumerate() {
        let Some(literal_word) = literal_words.get(index) else {
            return slash_suggestion_accepts_arguments(suggestion);
        };
        if !literal_word.starts_with(typed_word) {
            return false;
        }
    }
    true
}

pub(crate) fn slash_suggestion_accepts_arguments(suggestion: &SlashCommandSuggestion) -> bool {
    suggestion
        .usage
        .split_whitespace()
        .any(|word| word.starts_with('<') || word.starts_with('['))
}

pub(crate) fn split_slash_command_words(input: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut word_started = false;

    for ch in input.chars() {
        match quote {
            Some(quote_ch) if ch == quote_ch => {
                quote = None;
                word_started = true;
            }
            Some(_) => {
                word.push(ch);
                word_started = true;
            }
            None if ch.is_whitespace() => {
                if word_started {
                    words.push(std::mem::take(&mut word));
                    word_started = false;
                }
            }
            None if matches!(ch, '"' | '\'') && !word_started => {
                quote = Some(ch);
                word_started = true;
            }
            None => {
                word.push(ch);
                word_started = true;
            }
        }
    }

    if quote.is_some() {
        return Err("unterminated quoted string".to_owned());
    }
    if word_started {
        words.push(word);
    }
    Ok(words)
}

pub(crate) fn parse_chat_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command, name, members @ ..] if command == "new" => Ok(SlashCommand::ChatNew {
            name: name.clone(),
            members: members.to_vec(),
        }),
        [command] if command == "new" => Err("/chat new requires a name".to_owned()),
        [command, name @ ..] if command == "rename" && !name.is_empty() => {
            Ok(SlashCommand::ChatRename(name.join(" ")))
        }
        [command] if command == "rename" => Err("/chat rename requires a name".to_owned()),
        [command, description @ ..] if command == "describe" && !description.is_empty() => {
            Ok(SlashCommand::ChatDescribe(description.join(" ")))
        }
        [command] if command == "describe" => {
            Err("/chat describe requires a description".to_owned())
        }
        [command] if command == "archive" => Ok(SlashCommand::ChatArchive),
        [command] if command == "unarchive" => Ok(SlashCommand::ChatUnarchive),
        [command] if command == "archived" => Ok(SlashCommand::ChatArchived(true)),
        [command, value] if command == "archived" => {
            parse_on_off(value).map(SlashCommand::ChatArchived)
        }
        [] => {
            Err("/chat expects new, rename, describe, archive, unarchive, or archived".to_owned())
        }
        _ => Err("/chat expects new, rename, describe, archive, unarchive, or archived".to_owned()),
    }
}

pub(crate) fn parse_members_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command, members @ ..] if command == "add" && !members.is_empty() => {
            Ok(SlashCommand::MembersAdd(members.to_vec()))
        }
        [command] if command == "add" => {
            Err("/members add requires at least one member".to_owned())
        }
        [command, members @ ..] if command == "remove" && !members.is_empty() => {
            Ok(SlashCommand::MembersRemove(members.to_vec()))
        }
        [command] if command == "remove" => {
            Err("/members remove requires at least one member".to_owned())
        }
        [command] if command == "list" => Ok(SlashCommand::MembersList),
        [command, ..] if command == "list" => {
            Err("/members list does not accept arguments".to_owned())
        }
        [] => Err("/members expects add, remove, or list".to_owned()),
        _ => Err("/members expects add, remove, or list".to_owned()),
    }
}

pub(crate) fn parse_daemon_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command] if command == "status" => Ok(SlashCommand::DaemonStatus),
        [command] if command == "start" => Ok(SlashCommand::DaemonStart),
        [command, ..] if command == "start" => {
            Err("/daemon start does not accept arguments".to_owned())
        }
        [command] if command == "stop" => Ok(SlashCommand::DaemonStop),
        [] => Err("/daemon expects status, start, or stop".to_owned()),
        [command, ..] if command == "status" => {
            Err("/daemon status does not accept arguments".to_owned())
        }
        [command, ..] if command == "stop" => {
            Err("/daemon stop does not accept arguments".to_owned())
        }
        _ => Err("/daemon expects status, start, or stop".to_owned()),
    }
}

pub(crate) fn parse_account_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command] if matches!(command.as_str(), "create" | "add" | "import") => {
            Err("/account only selects identities; use /create-identity or /login".to_owned())
        }
        [selector] => Ok(SlashCommand::Account(selector.clone())),
        [] => Err("/account expects a selector".to_owned()),
        _ => Err("/account expects exactly one selector".to_owned()),
    }
}

pub(crate) fn parse_keys_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command, account] if command == "fetch" => Ok(SlashCommand::KeysFetch(account.clone())),
        [command] if command == "rotate" => Ok(SlashCommand::KeysRotate),
        _ => Err("/keys expects 'fetch <npub-or-hex>' or 'rotate'".to_owned()),
    }
}

pub(crate) fn parse_profile_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command, name @ ..] if command == "name" && !name.is_empty() => {
            Ok(SlashCommand::ProfileName(name.join(" ")))
        }
        [command] if command == "name" => Err("/profile name requires a name".to_owned()),
        [] => Err("/profile expects name <display-name>".to_owned()),
        _ => Err("/profile expects name <display-name>".to_owned()),
    }
}

pub(crate) fn parse_profile_name_command(args: Vec<String>) -> Result<SlashCommand, String> {
    if args.is_empty() {
        return Err("/name requires a name".to_owned());
    }
    Ok(SlashCommand::ProfileName(args.join(" ")))
}

pub(crate) fn parse_stream_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command, rest @ ..] if command == "start" => parse_stream_start(rest),
        [command, rest @ ..] if command == "watch" => parse_stream_watch(rest),
        [command] if command == "status" => Ok(SlashCommand::StreamStatus),
        [command, ..] if command == "status" => {
            Err("/stream status does not accept arguments".to_owned())
        }
        [command, stream_id, transcript_hash, chunk_count, text @ ..]
            if command == "finish" && !text.is_empty() =>
        {
            let chunk_count = chunk_count
                .parse::<u64>()
                .map_err(|_| "/stream finish chunk-count must be an integer".to_owned())?;
            Ok(SlashCommand::StreamFinish {
                stream_id: stream_id.clone(),
                transcript_hash: transcript_hash.clone(),
                chunk_count,
                text: text.join(" "),
            })
        }
        [command, ..] if command == "finish" => Err(
            "/stream finish expects <stream-id> <transcript-hash> <chunk-count> <text>".to_owned(),
        ),
        [command, stream_id, transcript_hash] if command == "verify" => {
            Ok(SlashCommand::StreamVerify {
                stream_id: stream_id.clone(),
                transcript_hash: transcript_hash.clone(),
                chunk_count: None,
            })
        }
        [command, stream_id, transcript_hash, chunk_count] if command == "verify" => {
            let chunk_count = chunk_count
                .parse::<u64>()
                .map_err(|_| "/stream verify chunk-count must be an integer".to_owned())?;
            Ok(SlashCommand::StreamVerify {
                stream_id: stream_id.clone(),
                transcript_hash: transcript_hash.clone(),
                chunk_count: Some(chunk_count),
            })
        }
        [command, ..] if command == "verify" => {
            Err("/stream verify expects <stream-id> <transcript-hash> [chunk-count]".to_owned())
        }
        rest => parse_stream_compose(rest),
    }
}

pub(crate) fn parse_stream_compose(args: &[String]) -> Result<SlashCommand, String> {
    let mut stream_id = None;
    let mut quic_candidates = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--stream-id" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err("/stream --stream-id requires a value".to_owned());
                };
                stream_id = Some(value.clone());
            }
            "--quic-candidate" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err("/stream --quic-candidate requires a value".to_owned());
                };
                quic_candidates.push(value.clone());
            }
            value if value.starts_with("--") => {
                return Err(format!("unknown /stream option: {value}"));
            }
            value => quic_candidates.push(value.to_owned()),
        }
        index += 1;
    }
    if quic_candidates.is_empty() {
        quic_candidates.push(DEFAULT_STREAM_CANDIDATE.to_owned());
    }
    Ok(SlashCommand::StreamCompose {
        stream_id,
        quic_candidates,
    })
}

pub(crate) fn parse_stream_start(args: &[String]) -> Result<SlashCommand, String> {
    let mut stream_id = None;
    let mut quic_candidates = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--stream-id" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err("/stream start --stream-id requires a value".to_owned());
                };
                stream_id = Some(value.clone());
            }
            "--quic-candidate" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err("/stream start --quic-candidate requires a value".to_owned());
                };
                quic_candidates.push(value.clone());
            }
            value if value.starts_with("--") => {
                return Err(format!("unknown /stream start option: {value}"));
            }
            value => quic_candidates.push(value.to_owned()),
        }
        index += 1;
    }
    if quic_candidates.is_empty() {
        return Err("/stream start requires at least one QUIC candidate".to_owned());
    }
    Ok(SlashCommand::StreamStart {
        stream_id,
        quic_candidates,
    })
}

pub(crate) fn parse_stream_watch(args: &[String]) -> Result<SlashCommand, String> {
    let mut stream_id = None;
    let mut insecure_local = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--stream-id" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err("/stream watch --stream-id requires a value".to_owned());
                };
                stream_id = Some(value.clone());
            }
            "--insecure-local" => insecure_local = true,
            value if value.starts_with("--") => {
                return Err(format!("unknown /stream watch option: {value}"));
            }
            value if stream_id.is_none() => stream_id = Some(value.to_owned()),
            _ => return Err("/stream watch accepts at most one stream id".to_owned()),
        }
        index += 1;
    }
    Ok(SlashCommand::StreamWatch {
        stream_id,
        insecure_local,
    })
}

pub(crate) fn parse_on_off(value: &str) -> Result<bool, String> {
    match value {
        "on" | "true" | "yes" => Ok(true),
        "off" | "false" | "no" => Ok(false),
        _ => Err("expected on or off".to_owned()),
    }
}
