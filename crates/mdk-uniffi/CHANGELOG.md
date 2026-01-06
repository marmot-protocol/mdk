# Changelog

<!-- All notable changes to this project will be documented in this file. -->

<!-- The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), -->
<!-- and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). -->

<!-- Template

## Unreleased

### Breaking changes

### Changed

### Added

### Fixed

### Removed

### Deprecated

-->

## Unreleased

### Breaking changes

### Changed

- **Bindings Security**: Updated bindings to use `Secret<T>` wrapper for secret values, ensuring automatic memory zeroization ([#109](https://github.com/marmot-protocol/mdk/pull/109))

### Added

- Added `get_pending_welcomes_paginated()` method to expose pagination to foreign language bindings ([#110](https://github.com/marmot-protocol/mdk/pull/110))

### Fixed

- **Security**: Secret values in bindings now use `Secret<T>` wrapper for automatic memory zeroization, preventing sensitive cryptographic material from persisting in memory ([#109](https://github.com/marmot-protocol/mdk/pull/109))

### Removed

### Deprecated

## [0.5.3] - 2025-12-09

First bindings release ([commit](https://github.com/marmot-protocol/mdk/commit/8d05c9b499564277bdd1d1fe27fcc702eadf4d54))