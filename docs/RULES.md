# Rules and risk model

All rules are deterministic and evidence-linked. A finding exists only if the rule's evidence requirement is met.

| ID | Severity | Rule |
|---|---|---|
| SMS-STL-001 | info | STARTTLS/STLS negotiation observed |
| SMS-STL-002 | medium | STARTTLS/STLS rejected by server |
| SMS-STL-003 | medium | TLS offered but session continued in plaintext |
| SMS-STL-004 | high | Authentication attempted without TLS (credentials never stored) |
| SMS-TLS-001 | high | Deprecated TLS/SSL version negotiated |
| SMS-TLS-002 | low | Client offers deprecated TLS versions |
| SMS-TLS-010 | info | TLS handshake incomplete in capture |
| SMS-TLS-011 | info | ClientHello not observed |
| SMS-TLS-012 | info | ServerHello not observed |
| SMS-TLS-013 | info | Insufficient evidence to assess TLS posture |
| SMS-TLS-014 | info | Modern TLS configuration observed |
| SMS-CIP-001 | high | Legacy/weak cipher suite selected |
| SMS-CIP-002 | low | Weak cipher suites offered by client |
| SMS-CIP-003 | medium | Cipher suite without forward secrecy selected |
| SMS-CRT-001 | high | Expired certificate observed |
| SMS-CRT-002 | medium | Certificate not yet valid |
| SMS-CRT-003 | medium | Weak certificate signature algorithm |
| SMS-CRT-004 | medium | Weak certificate public key |
| SMS-CRT-005 | info | Certificate evidence unavailable (e.g. TLS 1.3) |
| SMS-CRT-006 | low | Self-signed leaf certificate |
| SMS-CRT-007 | low | Presented chain lacks issuer certificate |
| SMS-CRT-008 | medium | Leaf certificate does not match SNI |

Full descriptions, detection logic, evidence requirements and remediation for each rule are shown in the **Rules** page and `GET /api/rules`.
Rules may be disabled; this creates a new rule-set version recorded on each analysis.

## SMRS-1 risk score (0–100)
`score = base(severity) × observation factor × completeness factor + multi-session bonus + credential bonus`

- base: critical 90 · high 70 · medium 45 · low 20 · info 5
- observation factor: weakness observed 1.0 · weak option offered 0.6 · protocol feature 0.5 · insufficient evidence 0.4 · secure configuration 0.2
- completeness factor: complete 1.0 · partial 0.85 · incomplete 0.6
- multi-session bonus: `min(10, 3 × (n − 1))` for n sessions triggering the same rule (not applied to info-level rules); credential bonus 5 for SMS-STL-004
- result clamped to 0–100

It is a transparent prioritisation aid. It is **not CVSS** and not a probability of compromise. Each finding lists its factors.
(Exact factor constants live in `backend/app/services/risk_engine.py`.)
