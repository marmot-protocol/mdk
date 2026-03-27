//! Error types for the messages module

storage_error! {
    /// Error types for the messages module
    pub enum MessageError {
        /// Message not found or not in expected state
        #[error("Message not found or not in expected state")]
        NotFound,
    }
}
