### Fixed

- Paced due maintenance `SelfUpdate` commits to at most two per maintenance pass, prioritizing manual and post-join rotations ahead of periodic leaf-refresh backlogs so multi-group upgrades or resumes do not trigger burst commit storms.
