### Fixed

- `wn-agent` answers a control request it cannot read with an `error` response instead of closing the connection
  silently (mdk#2242): `unsupported_protocol` for a missing or wrong `marmot_agent_control`, `unknown_request` for an
  unknown `type`, and `invalid_request` for anything else, echoing the request `id` when it could be read.
