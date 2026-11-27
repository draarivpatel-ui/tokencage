## Summary

Describe the change and its security impact.

## Compatibility

State whether the change affects token format, hash format, record format, CLI output, types or documented behavior.

## Verification

- [ ] `npm test`
- [ ] `node scripts/build-cjs.mjs --check`
- [ ] `npm run smoke`
- [ ] `npm pack --dry-run`

## Secret hygiene

- [ ] No real token, pepper, password or private key appears in this pull request
- [ ] Tests use generated or clearly artificial values
