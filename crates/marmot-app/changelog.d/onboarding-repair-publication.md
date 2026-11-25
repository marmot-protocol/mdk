### Fixed

- Approved onboarding repairs try the host's remaining default and inbox relays when the usual targets do not acknowledge publication (#3723). MDK backs off before retrying rate limits and missing acknowledgments and reports per-relay findings. After a definitive publication failure, users can cancel the repair or edit its relay list and approve a new signature. Retry keeps the original signed event, including after a restart.
