### Fixed

- Existing-key sign-in tries configured relays when the account's write relays fail to acknowledge its first KeyPackage. The fallback respects read-only relay declarations. Sign-in confirms a fallback publication only when a fresh inviter can select that same signed KeyPackage. If either publication or discovery fails, the user can review a write-relay change. Retries reuse the signed KeyPackage and its recorded acknowledgment while the package remains valid, including when relays refuse another write.
