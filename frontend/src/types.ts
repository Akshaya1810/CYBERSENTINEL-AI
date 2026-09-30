export type IncidentSeverity = 'Critical' | 'High' | 'Medium' | 'Low'
export type IncidentStatus = 'Open' | 'Investigating' | 'Resolved' | 'Closed'

export interface Incident {
  id: number
  title: string
  description: string | null
  severity: IncidentSeverity
  status: IncidentStatus
  source_ip: string | null
  created_at: string
  updated_at: string
}

export interface SecurityEvent {
  id: number
  incident_id: number | null
  event_type: string
  description: string
  source_ip: string | null
  timestamp: string | null
  raw_log: string | null
  username: string | null
  hostname: string | null
}

export interface InvestigationResult {
  id: number
  incident_id: number
  agent_name: string
  findings: string
  confidence: number | null
  created_at: string
}

export interface IncidentDetail extends Incident {
  security_events: SecurityEvent[]
  investigation_results: InvestigationResult[]
}

export interface IncidentCreateInput {
  title: string
  description: string
  severity: IncidentSeverity
  source_ip?: string
}

export interface IncidentUpdateInput {
  severity?: IncidentSeverity
  status?: IncidentStatus
}

export interface SecurityEventCreateInput {
  event_type: string
  description: string
  source_ip?: string
  raw_log?: string
  timestamp?: string
}

export interface InvestigationResultCreateInput {
  agent_name: string
  findings: string
  confidence?: number
}

export interface HealthStatus {
  status: string
  service?: string
}

export interface DatabaseHealth {
  status: string
  database: string
}

export interface DetectionRule {
  rule_id: string
  name: string
  severity: IncidentSeverity
  threshold: number
  window_seconds: number
  description: string
}

export interface DetectionHistoryItem {
  id: number
  rule_id: string
  rule_name: string
  severity: IncidentSeverity
  description: string
  source_ip: string
  incident_id: number
  detected_at: string
  event_ids: number[]
}

export interface MalformedLogRecord {
  record_number: number
  reason: string
}

export interface DetectionResult {
  id: number | null
  rule_id: string
  rule_name: string
  severity: IncidentSeverity
  source_ip: string
  description: string
  incident_id: number
  detected_at: string | null
  event_ids: number[]
  triggering_event_ids: number[]
}

export interface LogUploadSummary {
  filename: string
  file_format: string
  processed_records: number
  rejected_records: number
  malformed_records: MalformedLogRecord[]
  warning_count: number
  warnings: string[]
  detections: DetectionResult[]
}

export interface VerificationClaimCheck {
  text: string
  claim_type: 'fact' | 'hypothesis'
  status: 'supported' | 'unsupported' | 'unverified' | 'contradicted'
  event_ids: number[]
  reasons: string[]
}

export interface VerificationRecommendationCheck {
  text: string
  action_type: 'review_logs' | 'block_source_ip' | 'rate_limit_source_ip' | 'disable_account' | 'reset_password' | 'other'
  consistency: 'consistent' | 'unsupported' | 'unverified'
  approval_status: 'pending' | 'approved' | 'rejected' | 'not_required'
  event_ids: number[]
  reasons: string[]
}

export interface VerificationReport {
  status: 'verified' | 'partially_verified' | 'unverified' | 'contradicted'
  supported_claims: VerificationClaimCheck[]
  unsupported_claims: VerificationClaimCheck[]
  warnings: string[]
  contradictions: string[]
  missing_evidence: string[]
  recommendations: VerificationRecommendationCheck[]
}

export interface IncidentReport {
  incident: Pick<Incident, 'id' | 'title' | 'status' | 'severity' | 'created_at'> & { summary: string | null }
  timeline: Pick<SecurityEvent, 'id' | 'timestamp' | 'event_type' | 'source_ip' | 'username' | 'description' | 'raw_log'>[]
  source_ips: string[]
  affected_accounts: string[]
  detections: { rule_id: string; rule_name: string; severity: IncidentSeverity; description: string; event_ids: number[]; detected_at: string }[]
  attack_mappings: { technique_id: string; name: string; description: string; source_url: string; qualification: string }[]
  investigation_findings: { id: number; agent_name: string; findings: string; confidence: number | null; created_at: string; verification: string }[]
  ai_investigations: InvestigationRun[]
  response_recommendations: { text: string; approval_status: string }[]
  verification: VerificationReport
  limitations: string[]
}

export interface InvestigationStatement {
  classification: 'observed_fact' | 'hypothesis'
  text: string
  event_ids: number[]
  source_ip: string | null
  username: string | null
  hostname: string | null
  timestamp: string | null
  successful_login: boolean | null
}

export interface InvestigationNarrative {
  summary: string
  event_ids: number[]
  uncertainty: string
}

export interface InvestigationAnalysis {
  summary: string | null
  summary_event_ids: number[]
  triage: InvestigationNarrative
  findings: InvestigationStatement[]
  attack_reconstruction: InvestigationNarrative
  impact_assessment: { observed: InvestigationStatement[]; potential: InvestigationStatement[] }
  risk_assessment: { level: 'low' | 'medium' | 'high' | 'critical' | 'unknown'; rationale: string; event_ids: number[]; uncertainty: string }
  response_recommendations: { text: string; action_type: VerificationRecommendationCheck['action_type']; event_ids: number[]; source_ip: string | null; username: string | null }[]
}

export interface PipelineModuleStatus {
  module: string
  responsibility: string
  method: 'deterministic' | 'ollama' | 'independent_deterministic'
  status: 'completed' | 'unavailable' | 'failed'
}

export interface InvestigationRun {
  status: 'completed' | 'unavailable' | 'failed'
  provider: 'ollama'
  model: string
  inference_used: boolean
  investigation_result_id: number | null
  generated_at: string | null
  analysis: InvestigationAnalysis | null
  verification: VerificationReport | null
  modules: PipelineModuleStatus[]
  error_message: string | null
}
