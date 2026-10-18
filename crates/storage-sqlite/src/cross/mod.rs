//! Code that touches both the protocol and the app side, in one transaction
//! because both live in one database file. Each function is one named
//! crossing; `base::boundary_tests` lets only this folder name both sides.
//! The crossings still to move are listed in `allow-list.txt`; see `README.md`.

pub(crate) mod authority;
pub(crate) mod groups;
mod handles;
pub(crate) mod outbound;
pub(crate) mod projection;
pub(crate) mod release;
pub(crate) mod routes;
pub(crate) mod views;
mod wipe;
