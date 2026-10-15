# Development

Lemonbox supports a Linux x86_64 host with rootless Podman and KVM, a Debian 13 guest, and one owned IPv4 VPS reachable through the fixed two-hop Hysteria 2 route.

- [Architecture](architecture.md): state, lifecycle and enforcement.
- [Validation](validation.md): offline and live checks.
- [Detection limits](redteam.md): what a guest or service provider can observe.
- [Original full review](full-review-2026-10-14.md): the findings that prompted this refactor.
- [Python review](python-review.md): purpose and simplification of every Python module.
- [Cleanup results](cleanup-results.md): final changes and measured checks.

Run the offline suite once per completed batch from the repository root (about three seconds):

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -q
```

The application uses the Python standard library. Host diagnostics are application code; tests do not provide runtime dependencies. Private profiles, credentials, reports and images live outside this checkout.
