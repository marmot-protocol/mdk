# Changelog

## Unreleased

### Breaking changes

- Remove `AnnouncedKeyPackage`, `AnnouncedKeyPackageStorage`, its retention
  and per-slot limits, and `StorageProvider::announced_key_package_storage`
  (mdk#2863, D81). The unused announcement history has no replacement.
