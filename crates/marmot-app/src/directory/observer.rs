//! Product analytics for directory operations. `marmot-app` implements
//! [`DirectoryObserver`] over its usage-diagnostics collector, with the same
//! family, operation and unit strings the directory reported before (step 3,
//! decision 4 of `docs/marmot-architecture/review/brief-directory.md`).

/// The analytics family an operation reports under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedFamily {
    Directory,
    KeyPackage,
}

/// What one observation counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedUnit {
    Action,
    Attempt,
}

/// Starts observations of directory operations.
pub trait DirectoryObserver {
    type Observation: DirectoryObservation;

    /// `None` while diagnostics are off.
    fn begin(
        &self,
        family: ObservedFamily,
        operation: &'static str,
        unit: ObservedUnit,
    ) -> Option<Self::Observation>;
}

/// One operation in progress. Dropping it unfinished records a cancellation,
/// unless [`Self::counts_only`] turned that off.
pub trait DirectoryObservation: Send + 'static {
    /// Mark it finished, so dropping it records no cancellation. Its counts
    /// and samples still record.
    fn counts_only(self) -> Self;

    fn count(&self, outcome: &str, unit: ObservedUnit, count: u64);

    /// Attribute a directory result to its finite origin (`cache`, `network`
    /// or `mixed`), never to an endpoint.
    fn directory_sample(&self, outcome: &str, source: &str, count: u64);

    fn finish(self, outcome: &str);

    /// End without recording a duration or a cancellation.
    fn discard(self);
}
