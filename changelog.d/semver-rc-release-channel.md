### Changed

- Replaced dated nightly pre-releases (`*-nightly.YYYYMMDD`, `nightly-meta/latest.json`) with daily canary-gated SemVer Release Candidates (`<track>-vX.Y.Z-rc.N`, `rc-meta:rc/latest.json` schema 2, `rc/signature_delta.json`) and one-click Stable promotion (`promote-release.yml` / `just promote-rc`).

### Removed

- Retired the `nightly-releases.yml` workflow and `nightly-meta/latest.json` update stream; retention continues expiring legacy `*-nightly.*` pre-releases older than 30 days.
