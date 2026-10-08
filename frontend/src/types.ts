// Shapes returned by the API (backend/app/api/*.py and the report dataset).

export type Role = "admin" | "consultant";
export type Provider = "aws" | "azure";
export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type JobStatus = "queued" | "running" | "succeeded" | "failed";
export type Stage = "waiting" | "connecting" | "collecting" | "evaluating" | "saving" | "done";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];

export interface Me {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  must_change_password: boolean;
  mfa_enabled: boolean;
  consultancy: string;
}

export interface LoginResult {
  mfa_enrolled: boolean;
  next_step: "mfa_setup" | "mfa_verify";
}

export interface MfaSetup {
  secret: string;
  otpauth_uri: string;
}

export interface RecoveryCodes {
  recovery_codes: string[];
  note: string;
}

export interface Client {
  id: string;
  name: string;
  created_at: string;
}

export interface Connection {
  id: string;
  provider: Provider;
  account_id: string;
  external_id: string | null;
  tenant_id: string | null;
  created_at: string;
}

export interface AwsConnectionResult {
  connection: Connection;
  setup: { role_name: string; external_id: string; template: string };
}

export interface Assessment {
  id: string;
  connection_id: string;
  name: string;
  status: "draft" | "in_review" | "finalized";
  created_at: string;
}

export interface ScanRunSummary {
  id: string;
  provider: Provider;
  account_id: string;
  regions: string[];
  started_at: string;
  completed_at: string;
  findings: number;
}

export interface AssessmentDetail extends Assessment {
  scans: ScanRunSummary[];
  finalization: Finalization | null;
}

export interface ScanJob {
  id: string;
  assessment_id: string;
  status: JobStatus;
  stage: Stage;
  regions: string[] | null;
  requested_at: string;
  started_at: string | null;
  finished_at: string | null;
  error_code: string | null;
  error_message: string | null;
  scan_run_id: string | null;
}

export interface OverviewItem {
  client_id: string;
  client_name: string;
  assessment_id: string;
  assessment_name: string;
  assessment_status: Assessment["status"];
  provider: Provider;
  account_id: string;
  latest_scan: {
    id: string;
    completed_at: string;
    findings: number;
    by_severity: Record<Severity, number>;
  } | null;
  active_job: { id: string; status: JobStatus; stage: Stage } | null;
}

export interface Overview {
  clients: number;
  items: OverviewItem[];
}

export interface Evidence {
  source_operation: string;
  collected_at: string;
  summary: string;
  observed: Record<string, unknown>;
}

export interface FrameworkRef {
  framework: string;
  framework_name: string;
  version: string;
  control_id: string;
  title: string;
  verified: boolean;
}

export type ReviewStatus = "open" | "confirmed" | "false_positive" | "accepted_risk";

export interface FindingReviewInfo {
  status: ReviewStatus;
  original_severity: Severity;
  severity_overridden: boolean;
  justification: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
}

export interface ReviewEvent {
  occurred_at: string;
  actor: string;
  status: ReviewStatus;
  severity_override: Severity | null;
  justification: string | null;
  previous_status: ReviewStatus | null;
  previous_severity_override: Severity | null;
}

export interface Finalization {
  id: string;
  scan_run_id: string;
  finalized_at: string;
  finalized_by: string;
  report_sha256: string;
}

export interface Finding {
  finding_id: string;
  rule_id: string;
  title: string;
  provider: Provider;
  account_id: string;
  category: string;
  severity: Severity;
  resource_id: string | null;
  resource_name: string | null;
  resource_type: string | null;
  region: string | null;
  message: string;
  description: string;
  risk: string;
  recommendation: string;
  evidence: Evidence[];
  framework_refs: FrameworkRef[];
  detected_at: string;
  review: FindingReviewInfo;
}

export interface Report {
  schema_version: string;
  generated_at: string;
  source: {
    consultancy: string;
    client_name: string;
    assessment_id: string;
    assessment_name: string;
    assessment_status: string;
    scan_id: string;
    scan_sha256: string;
    report_status: "draft" | "final";
    finalized_at: string | null;
    finalized_by: string | null;
  };
  provider: Provider;
  account_id: string;
  regions: string[];
  scan_started_at: string;
  scan_completed_at: string;
  summary: {
    total_findings: number;
    by_severity: Record<Severity, number>;
    by_category: Record<string, number>;
    checks_by_status: Record<string, number>;
    rules_run: number;
    by_review_status: Partial<Record<ReviewStatus, number>>;
  };
  findings: Finding[];
  accepted_risks: Finding[];
  false_positives: Finding[];
  not_evaluated: { rule_id: string; region: string | null; reason: string }[];
  notes: string[];
}

export interface AdminUser {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  is_active: boolean;
  mfa_enabled: boolean;
  must_change_password: boolean;
  locked: boolean;
  last_login_at: string | null;
  created_at: string;
  client_ids: string[];
}

export interface TemporaryPassword {
  user: AdminUser;
  temporary_password: string;
  note: string;
}

export interface AuditEvent {
  id: string;
  occurred_at: string;
  action: string;
  outcome: string;
  actor_type: string;
  actor_user_id: string | null;
  actor_email: string | null;
  client_id: string | null;
  target_type: string | null;
  target_id: string | null;
  ip_address: string | null;
  details: Record<string, unknown>;
}

export interface InviteInfo {
  email: string;
  display_name: string;
  role: Role;
  consultancy: string;
}

export interface Invite {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  created_by: string;
  created_at: string;
  expires_at: string;
}

export interface InviteCreated {
  invite: Invite;
  token: string;
  note: string;
}
