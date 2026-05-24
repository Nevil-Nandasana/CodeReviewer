// Shared TypeScript types for the CodeReviewer frontend

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
// 'skipped' is set by the backend when a PR exceeds MAX_DIFF_SIZE_KB. It is a
// deliberate non-result, not a failure, and the UI distinguishes the two.
export type ReviewStatus = 'pending' | 'running' | 'complete' | 'error' | 'skipped'
export type VulnStatus = 'open' | 'resolved' | 'false_positive'

export interface Review {
  id: string
  pull_request_id: string
  status: ReviewStatus
  model_used: string | null
  total_comments: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  overall_quality_score: number | null
  processing_time_seconds: number | null
  inference_time_seconds: number | null
  created_at: string
  completed_at: string | null
}

export interface ReviewComment {
  id: string
  file_path: string
  line_number: number | null
  severity: Severity
  category: string | null
  title: string | null
  explanation: string
  suggestion: string | null
  owasp_category: string | null
  is_false_positive: boolean
}

export interface PullRequest {
  id: string
  github_pr_number: number
  title: string | null
  author: string | null
  status: string
  base_branch: string | null
  head_branch: string | null
  repository_id: string
  created_at: string
  files_changed?: number
  lines_added?: number
  lines_deleted?: number
}

export interface Repository {
  id: string
  owner: string
  name: string
  full_name: string
  language: string | null
  review_enabled: boolean
  security_scan_enabled: boolean
  created_at: string
}

export interface Vulnerability {
  id: string
  file_path: string | null
  line_number: number | null
  vuln_type: string | null
  severity: Severity
  owasp_category: string | null
  title: string | null
  explanation?: string
  status: VulnStatus
  first_seen_at: string
  repository_id: string
}

export interface QualityMetric {
  id: string
  file_path: string | null
  language: string | null
  cyclomatic_complexity: number | null
  lines_of_code: number | null
  comment_ratio: number | null
  avg_function_length: number | null
  overall_quality_score: number | null
  created_at: string
}

export interface DashboardSummary {
  total_prs_reviewed: number
  reviews_this_week: number
  critical_open: number
  high_open: number
  avg_quality_score: number | null
}
