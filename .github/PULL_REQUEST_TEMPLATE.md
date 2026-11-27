## Summary

Describe the security behavior changed and why.

## Attack scenario or defect

Explain the concrete input or threat model this addresses. Use synthetic values only.

## Verification

- [ ] `npm test` passes and the exact test count is reported
- [ ] `node scripts/build-cjs.mjs --check` passes
- [ ] `npm pack --dry-run` was inspected
- [ ] ESM and CommonJS behavior were kept in sync
- [ ] TypeScript declarations were updated for public API changes
- [ ] README.md scope and limitations were updated when needed

## Risk

List compatibility breaks, new error codes or deliberate behavior changes. Write "none" if there are none.
