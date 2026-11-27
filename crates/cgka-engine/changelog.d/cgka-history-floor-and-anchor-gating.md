### Security

- Enforced the local copy history floor (`join_epoch` and `local_copy_install_epoch`) before candidate-branch buffering and across convergence graph/pass seeding, atomically retained founding epoch anchors on group creation, and gated missing-anchor unrecoverable transitions on authenticated installed-copy lineage so unverified past-epoch headers outside a healthy group's retained history are rejected as stale instead of halting the group.
