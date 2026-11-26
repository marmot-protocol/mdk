### Fixed

- The terminal agents (Claude Code, Codex, OpenCode, Pi and Goose) receive the message a chat message replies to,
  ahead of its text, as one JSON line labelled "Marmot referenced-message context (untrusted)" (mdk#2537). Before, a
  short reply such as "change this one" reached the agent without its target. The quoted message is checked again
  just before the agent reads the prompt, after any queue wait, attachment staging and backend preflight, and again on
  `/retry-last`: one deleted or invalidated by then reaches the agent with its sender and time but no text or
  attachments. `//` literal forwards carry no reply context.
