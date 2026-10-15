# Publishing

This repository starts with sanitized source and fresh Git history. The original private repository and its history were archived separately and are not included here.

The route example uses documentation-only IP addresses, example TLS names and placeholder credentials. Replace them through Lemonbox setup; keep real route settings, SSH identities, VM disks and validation reports in private host state. Shared workspace contents are excluded from Git and container builds.

The initial public history uses the generic identity `Lemonbox contributors <contributors@lemonbox.invalid>`. Before making personally attributed public commits, set the public name and email you want attached to them:

```sh
git config user.name YOUR_PUBLIC_NAME
git config user.email YOUR_PUBLIC_COMMIT_EMAIL
```

Use your Git hosting account's private/noreply commit email if you do not want a personal email published. The generic identity remains configured locally until changed. The new repository has no remote configured.

The preparation audit found no credential-pattern matches or saved route password/private-key matches in the original reachable file history. Deployment IPs and personal names/paths were removed from examples, fixtures and historical reports. Live packet and fault tools now require explicit deployment addresses. Private environment files, SSH/access state and common private-key formats are ignored.

Before publishing later changes, review the staged diff and commit identities as well as the current files; deleting sensitive content in a later commit does not erase earlier versions.
