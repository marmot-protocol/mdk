### Fixed

- Expired KeyPackages can now be retired from local MLS storage after their lifetime elapses, and session maintenance no longer republishes, fans out, or retains expired pending or current KeyPackages (mdk#3730).
- Fallback KeyPackage relay routing now excludes relays that the account's NIP-65 list explicitly declared as read-only when declared write relays are empty or unsafe, and persisted KeyPackage retries honor current relay policy without stranding empty-route intents (mdk#3730).
- Background KeyPackage maintenance (startup cutover, worker maintenance, KeyPackage catch-up, and automatic group-recovery recipient Challenge publication) is now deferred while interactive onboarding is unfinished, unifying invite/group recovery and KeyPackage catch-up under `maintenance_passes` (mdk#3730).
