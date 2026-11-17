// OpenClaw Doctor contract. The host resolves the built `dist/doctor-contract-api.js`
// during install, update, and `openclaw doctor`; a manifest `doctorContract` without
// a loadable module blocks plugin updates.
//
// The adapter owns no OpenClaw state that needs migrating. `wn-agent` owns the Marmot
// database, and the adapter's own files (profile-onboarding status, outbound media
// staging) live under the wn-agent home, outside OpenClaw's state directory. Keep this
// list in the same order as `doctorContract.stateMigrations` in `openclaw.plugin.json`.
// Keep it free of runtime SDK imports so it loads on every supported host.
export const stateMigrations: readonly never[] = [];
