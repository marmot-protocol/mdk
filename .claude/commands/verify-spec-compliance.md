Please verify code compliance with the Marmot Protocol specification: $ARGUMENTS.

Follow these steps:

1. Identify the feature/component to verify from the arguments
2. Review the Marmot Protocol spec in `/marmot` workspace folder
3. Review relevant MLS RFCs (RFC 9420, RFC 9750) if applicable
4. Review relevant Nostr NIPs if applicable
5. Compare implementation with specification:
   - Protocol message formats
   - State machine behavior
   - Cryptographic operations
   - Error handling
   - Edge cases
6. Identify any deviations or ambiguities
7. Document findings:
   - What matches the spec
   - What deviates (and why, if intentional)
   - What is unclear in the spec
8. If fixes are needed:
   - Implement corrections
   - Add tests to verify spec compliance
   - Update documentation
   - Add changelog entry
9. Run `just precommit` to ensure all checks pass
10. Create a descriptive commit message
11. Push and create a PR

Spec compliance checklist:
- ✅ Message formats match spec
- ✅ State transitions match spec
- ✅ Cryptographic operations match spec
- ✅ Error handling matches spec
- ✅ Edge cases handled per spec
- ✅ Tests verify spec compliance
