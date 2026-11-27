### Fixed

- Unified GroupContext admin-policy (`0x8003`) and group-lifecycle (`0x800c`) validation across Legacy and Current profiles, rejected caller-supplied `0x800c` overrides during group creation and `UpdateAppComponents`, rejected joining `Disbanded` Welcomes in both profiles, and tightened wire bounds on `DeviceRosterV1::devices` and `SiblingWelcome::decode` relay lists (#3795, #2455, #2456).
