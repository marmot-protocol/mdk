//! Complete selection capture's private native/host presentation boundary.
//! Native owns candidates and boolean composition; host answers only issued
//! presentation leaves after the SQL snapshot has been released.
pub(crate) mod capture;
pub(crate) mod presentation;
pub(crate) mod scope;
