## Summary

Describe the outcome of this change and why it is needed.

## Component

- [ ] Python backend/BFF
- [ ] Rust API
- [ ] Rust controller, remote helper, or SSH gateway
- [ ] PostgreSQL schema
- [ ] Caddy or Compose
- [ ] Documentation or CI

## Validation

List the commands and scenarios used to verify the change.

## Safety and compatibility

- [ ] Browser traffic still reaches platform APIs through the intended BFF or public API boundary.
- [ ] The Python backend has no direct database dependency.
- [ ] Runtime and object-operation state changes remain durable and controller-reconcilable.
- [ ] No secrets, tokens, flags, private keys, or participant data are included.
- [ ] Documentation and configuration examples are updated where needed.
