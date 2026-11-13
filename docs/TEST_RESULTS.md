# Test results - synthetic fixture regression

Generated automatically by `backend/tests/regression/test_fixture_regression.py` on 2026-11-13 06:51 UTC. 
Every value below was produced by running the real TShark-backed pipeline; nothing is hand-written.

| Fixture | Expected observation | Actual observation | Expected rules | Actual rules | Evidence IDs | Status |
|---|---|---|---|---|---|---|
| `smtp_starttls_tls12_complete.pcap` | smtp; TLSv1.2; TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | smtp; TLSv1.2; TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | SMS-STL-001, SMS-TLS-014 | SMS-STL-001, SMS-TLS-014 | SMS-STL-001:E-0001, SMS-TLS-014:E-0004 | **PASS** |
| `smtp_starttls_missing_handshake.pcap` | smtp; no TLS params; - | smtp; no TLS params; - | SMS-TLS-013 | SMS-TLS-013 | SMS-TLS-013:E-0001 | **PASS** |
| `imap_starttls.pcap` | imap; TLSv1.2; TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | imap; TLSv1.2; TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | SMS-STL-001, SMS-TLS-014 | SMS-STL-001, SMS-TLS-014 | SMS-STL-001:E-0001, SMS-TLS-014:E-0004 | **PASS** |
| `pop3_stls.pcap` | pop3; TLSv1.2; TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 | pop3; TLSv1.2; TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 | SMS-STL-001, SMS-TLS-014 | SMS-STL-001, SMS-TLS-014 | SMS-STL-001:E-0001, SMS-TLS-014:E-0004 | **PASS** |
| `smtp_deprecated_tls10.pcap` | smtp; TLSv1.0; TLS_RSA_WITH_3DES_EDE_CBC_SHA | smtp; TLSv1.0; TLS_RSA_WITH_3DES_EDE_CBC_SHA | SMS-CIP-001, SMS-CIP-002, SMS-CIP-003, SMS-CRT-001, SMS-CRT-003, SMS-CRT-004, SMS-CRT-006, SMS-TLS-001 | SMS-CIP-001, SMS-CIP-002, SMS-CIP-003, SMS-CRT-001, SMS-CRT-003, SMS-CRT-004, SMS-CRT-006, SMS-STL-001, SMS-TLS-001 | SMS-CIP-001:E-0004, SMS-CIP-002:E-0007, SMS-CIP-003:E-0005, SMS-CRT-001:E-0001, SMS-CRT-003:E-0006, SMS-CRT-004:E-0002, SMS-CRT-006:E-0008, SMS-TLS-001:E-0003 | **PASS** |
| `smtp_legacy_cipher_tls12.pcap` | smtp; TLSv1.2; TLS_RSA_WITH_RC4_128_SHA | smtp; TLSv1.2; TLS_RSA_WITH_RC4_128_SHA | SMS-CIP-001, SMS-CIP-002, SMS-CIP-003 | SMS-CIP-001, SMS-CIP-002, SMS-CIP-003, SMS-STL-001 | SMS-CIP-001:E-0001, SMS-CIP-002:E-0003, SMS-CIP-003:E-0002 | **PASS** |
| `smtp_starttls_tls13.pcap` | smtp; TLSv1.3; TLS_AES_256_GCM_SHA384 | smtp; TLSv1.3; TLS_AES_256_GCM_SHA384 | SMS-CRT-005, SMS-STL-001, SMS-TLS-014 | SMS-CRT-005, SMS-STL-001, SMS-TLS-014 | SMS-CRT-005:E-0001, SMS-STL-001:E-0002, SMS-TLS-014:E-0005 | **PASS** |
| `smtp_incomplete_clienthello_only.pcap` | smtp; no TLS params; - | smtp; no TLS params; - | SMS-TLS-012, SMS-TLS-013 | SMS-STL-001, SMS-TLS-012, SMS-TLS-013 | SMS-TLS-012:E-0004, SMS-TLS-013:E-0005 | **PASS** |
| `smtp_retransmit_reorder.pcap` | smtp; TLSv1.2; TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | smtp; TLSv1.2; TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | SMS-STL-001, SMS-TLS-014 | SMS-STL-001, SMS-TLS-014 | SMS-STL-001:E-0001, SMS-TLS-014:E-0004 | **PASS** |
| `smtp_plaintext_auth.pcap` | smtp; no TLS params; - | smtp; no TLS params; - | SMS-STL-003, SMS-STL-004 | SMS-STL-003, SMS-STL-004 | SMS-STL-003:E-0002, SMS-STL-004:E-0001 | **PASS** |
| `smtp_nonstandard_port.pcap` | smtp; TLSv1.2; TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | smtp; TLSv1.2; TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | SMS-STL-001, SMS-TLS-014 | SMS-STL-001, SMS-TLS-014 | SMS-STL-001:E-0001, SMS-TLS-014:E-0004 | **PASS** |
| `smtp_starttls_rejected.pcap` | smtp; no TLS params; - | smtp; no TLS params; - | SMS-STL-002 | SMS-STL-002 | SMS-STL-002:E-0001 | **PASS** |
| `corrupted.pcap` | -; no TLS params; - | -; no TLS params; - | - | - | - | **PASS** |
| `empty.pcap` | -; no TLS params; - | -; no TLS params; - | - | - | - | **PASS** |
| `unsupported_linktype.pcap` | -; no TLS params; - | -; no TLS params; - | - | - | - | **PASS** |

**15/15 fixtures passed.**
