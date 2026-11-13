# Security and privacy

- **Authorised use only.** Analyse captures you own or have permission to examine.
- **Local-only, no auth.** Binds to 127.0.0.1 by default; there is no login. Do not expose it to a network.
- **No sensitive storage.** Credentials (AUTH/LOGIN/USER/PASS), mail addresses and message bodies are never persisted or reported; placeholders such as `[credentials not stored]` are stored instead. Raw bytes are retained only for TLS handshake frames.
- **Uploads.** Validated by content (pcap/pcapng magic, supported link type, size limit), not by extension. Filenames are sanitised; stored paths are checked to stay inside the data dir (path-traversal guard). Duplicates are detected by SHA-256.
- **Subprocess.** TShark is invoked without a shell, with a whitelist of arguments, a timeout and a cancel path.
- **Output encoding.** HTML reports are autoescaped and served with a restrictive CSP; the in-app preview uses a sandboxed iframe. CSV export neutralises formula injection (`= + - @`).
- **AI.** Disabled by default. When enabled, it receives structured metadata only (never packets or payloads). In local-only mode non-loopback endpoints are refused. API keys come from environment variables and are never logged.
- **Audit log.** Uploads, deletions, settings and rule changes are recorded without sensitive values.
- **Retention.** Configurable; originals can be discarded, and capture deletion removes all derived data.
- **Not covered.** No certificate trust/revocation/hostname validation, no TLS decryption, no multi-user access control.
