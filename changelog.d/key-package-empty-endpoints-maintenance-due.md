### Fixed

- `AccountDeviceRuntime::key_package_network_maintenance_due` and `maintenance_due` no longer report KeyPackage publication work as continuously owed when zero writable KeyPackage publication endpoints are configured, while keeping private-material expiry deadlines scheduled (follow-up to #3777).
