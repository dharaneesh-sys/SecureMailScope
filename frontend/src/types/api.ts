export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingStatus = 'open' | 'under_review' | 'resolved' | 'accepted_risk'
export type ObservationType = 'weakness_observed' | 'weak_option_offered' | 'secure_configuration' | 'protocol_feature' | 'insufficient_evidence'
export type Completeness = 'complete' | 'partial' | 'incomplete'
export type AnalysisStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
export type ItemState = 'observed' | 'not_observed' | 'incomplete' | 'undecodable'

export interface Page<T> { items: T[]; total: number; page: number; page_size: number; pages: number }

export interface Capture {
  id: string; filename: string; sha256: string; size_bytes: number; format: string; linktype: string | null
  packet_count: number; uploaded_at: string; is_demo: boolean; retained: boolean; warnings: string[]
  latest_analysis?: { id: string; status: AnalysisStatus; findings: number; highest_severity: Severity | null; protocols: string[] } | null
  analysis_count?: number
}
export interface UploadResult { capture: Capture; duplicate: boolean; message: string }

export interface Counters { packets?: number; streams?: number; email_sessions?: number; tls_handshakes?: number; certificates?: number; findings?: number; evidence?: number }
export interface StageLog { key: string; label: string; status: 'running' | 'done' | 'failed'; message?: string; started_at?: string }
export interface Analysis {
  id: string; capture_id: string; capture: Capture | null; status: AnalysisStatus; stage: string | null; progress: number; counters: Counters
  messages: { t: string; stage: string; message: string }[]; stage_log: StageLog[]; error: string | null; failed_stage: string | null
  created_at: string; started_at: string | null; finished_at: string | null; ruleset_version: string | null; options: Record<string, boolean>
  highest_severity: Severity | null; protocols: string[]
  limitations?: string[]; engine_errors?: string[]; tool?: Record<string, unknown>; ai_summary?: AiSummary | null
}
export interface AnalysisStatusResp { id: string; status: AnalysisStatus; stage: string | null; progress: number; counters: Counters; messages: Analysis['messages']; stage_log: StageLog[]; error: string | null; failed_stage: string | null; stages: { key: string; label: string }[] }

export interface AiSummary { status: 'generated' | 'disabled' | 'error'; label: string; provider?: string; model?: string; executive_summary?: string; priorities?: { rule_id: string; rationale: string }[]; error?: string; message?: string }

export interface Evidence {
  id: string; ref: string; analysis_id: string; finding_id: string; capture: string | null; frame: number | null; stream_id: number | null; direction: string | null
  timestamp: string | null; protocol: string; description: string; fields: Record<string, unknown>; parser: string; completeness: Completeness
  finding?: { id: string; ref: string; title: string; severity: Severity; rule_id: string } | null
}
export interface RiskInfo { score: number; model: string; factors: { factor: string; value: string; effect: number }[]; explanation: string; recommended_action: string }
export interface Finding {
  id: string; ref: string; analysis_id: string; capture: string | null; capture_id: string | null; rule_id: string; title: string; severity: Severity; category: string
  protocol: string | null; stream_id: number | null; description: string; technical: string; impact: string; remediation: string; observation_type: ObservationType
  completeness: Completeness; risk_score: number; risk: RiskInfo; status: FindingStatus; created_at: string; rule_version: number; evidence_count: number
  evidence?: Evidence[]; history?: { old_status: string | null; new_status: string; note: string | null; at: string }[]
  session?: EmailSession | null; tls_session?: TlsSession | null; ruleset_version?: string
}

export interface ProtoEvent { frame: number; ts: string | null; direction: string; kind: string; verb: string; summary: string; state: string }
export interface EmailSession {
  stream_id: number; protocol: 'smtp' | 'imap' | 'pop3'; client: string; server: string; first_ts: string | null; last_ts: string | null; banner: string | null
  implicit_tls: boolean; detected_by: string; capabilities: string[]; starttls: { offered: boolean | null; command_frame: number | null; response_frame: number | null; accepted: boolean | null; tls_followed: boolean }
  events: ProtoEvent[]; states: Record<string, ItemState>; notes: string[]; completeness: Completeness
}
export interface TcpStream { stream_id: number; client: string; server: string; protocol: string | null; detected_by: string | null; frames: number; first_ts: string | null; last_ts: string | null; completeness: Completeness
  quality: { syn: boolean; fin: boolean; rst: boolean; retransmissions: number; out_of_order: number; lost_segments: number } }
export interface CipherSuite { id: string; name: string; weak_class: string | null; known: boolean }
export interface TlsSession {
  stream_id: number; carrier_protocol: string | null; via_starttls: boolean; client: string; server: string; record_versions: string[]
  client_hello: { frame: number; ts: string | null; legacy_version: string | null; supported_versions: string[]; sni: string | null; alpn: string[]; supported_groups: string[]; signature_algorithms: string[]; extensions: number[]; cipher_suites: CipherSuite[] } | null
  server_hello: { frame: number; ts: string | null; legacy_version: string | null; selected_version: string | null; version_source: string | null; cipher_suite: { id: string; name: string; weak_class: string | null; forward_secret: boolean | null; aead: boolean | null } | null; extensions: number[] } | null
  selected_version: string | null; selected_cipher: string | null; completeness: Completeness; notes: string[]
  flags: { tls13: boolean; ech: boolean; certificate_visible: boolean; server_hello_done: boolean; change_cipher_spec: boolean; encrypted_after_hello: boolean; alerts: string[]; frames: number[] }
}
export interface CertCheck { check: string; result: 'pass' | 'fail' | 'info' | 'unknown' | 'not_performed'; detail: string }
export interface Certificate { id: number; stream_id: number; position: number; frame: number | null; subject: string; issuer: string; serial: string; not_before: string; not_after: string; sig_algorithm: string; key_algorithm: string; key_size: number | null; san: string[]; sha256: string; self_signed: boolean; checks: CertCheck[] }

export interface Summary {
  analysis: Analysis; counters: Counters; severity: Record<Severity, number>; status: Record<string, number>; observation_types: Record<string, number>
  tls_versions: Record<string, number>; limitations: string[]; engine_errors: string[]; tool: Record<string, unknown>; certificates_observed: number
}

export interface Dashboard {
  metrics: { captures: number; analyses_completed: number; email_sessions: number; findings: number; critical_high: number; tls_sessions: number; success_rate: number | null; certificates: number }
  severity: Record<Severity, number>; findings_over_time: ({ date: string } & Record<Severity, number>)[]
  protocols: { name: string; value: number }[]; tls_versions: { name: string; value: number }[]; ciphers: { name: string; value: number }[]
  recent_analyses: Analysis[]; recent_findings: Finding[]; demo_loaded: boolean
}

export interface Rule { rule_id: string; name: string; category: string; severity: Severity; description: string; detection: string; evidence_requirements: string; remediation: string; references: string[]; enabled: boolean; version: number; findings_total: number }
export interface RulesResp { items: Rule[]; current_ruleset: string; history: { signature: string; created_at: string; note: string | null; enabled_count: number; total: number }[]; note: string }
export interface Report { id: string; analysis_id: string; capture: string | null; format: 'json' | 'html' | 'csv' | 'pdf'; filename: string; size_bytes: number; sha256: string; created_at: string }
export interface Dependencies { tshark: { available: boolean; path: string | null; version: string | null; editcap: string | null; error?: string }; python: string; guidance: string | null; limits: { max_upload_mb: number; analysis_timeout_s: number; max_packets: number } }
export interface AppSettings { local_only_mode: boolean; retention_days: number; retain_original_captures: boolean; max_upload_mb: number; cert_reference: 'capture' | 'analysis'; ai_provider: 'none' | 'ollama' | 'openai_compatible'; ai_endpoint: string; ai_model: string; report_organisation: string; report_include_hex: boolean; analyst_name: string }
export interface EvidenceDetail { evidence: Evidence; finding: Finding; packet: { frame: number; tree: Record<string, unknown> | null; raw_hex: string | null; protocol: string } | null; session: EmailSession | null; tls_session: TlsSession | null; capture: { id: string; filename: string; sha256: string }; analysis_id: string }
