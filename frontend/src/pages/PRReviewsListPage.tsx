import { useQuery } from '@tanstack/react-query'
import { reviewsApi } from '@/api/client'
import LoadingSpinner from '@/components/shared/LoadingSpinner'
import SeverityBadge from '@/components/shared/SeverityBadge'
import { GitPullRequest, Clock, ChevronRight, CheckCircle } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { formatDistanceToNow } from 'date-fns'

export default function PRReviewsListPage() {
  const navigate = useNavigate()

  const { data: reviews = [], isLoading } = useQuery({
    queryKey: ['reviews-list'],
    queryFn: () => reviewsApi.list().then((r) => r.data),
  })

  const { data: prs = [] } = useQuery({
    queryKey: ['prs-list'],
    queryFn: () => reviewsApi.listPRs().then((r) => r.data),
  })

  if (isLoading) return <LoadingSpinner label="Loading reviews…" />

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
          <GitPullRequest size={24} className="text-brand-400" />
          PR Reviews
        </h1>
        <p className="text-slate-500 text-sm mt-0.5">All automated code review runs</p>
      </div>

      {reviews.length === 0 ? (
        <div className="card text-center py-20">
          <GitPullRequest size={40} className="text-slate-700 mx-auto mb-4" />
          <h3 className="text-slate-400 font-semibold mb-2">No reviews yet</h3>
          <p className="text-slate-600 text-sm max-w-sm mx-auto">
            Reviews are triggered automatically when a PR is opened via the GitHub webhook.
            Connect a repo and open a pull request to get started.
          </p>
        </div>
      ) : (
        <div className="card divide-y divide-slate-800/60 p-0 overflow-hidden">
          {(reviews as any[]).map((review) => (
            <button
              key={review.id}
              onClick={() => navigate(`/reviews/${review.id}`)}
              className="w-full text-left flex items-center gap-4 px-6 py-4 hover:bg-surface-800/40 transition-colors group"
            >
              <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${
                review.critical_count > 0 ? 'bg-red-500' :
                review.high_count > 0 ? 'bg-orange-500' :
                review.status === 'complete' ? 'bg-emerald-500' : 'bg-slate-500'
              }`} />

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  {review.critical_count > 0 && <SeverityBadge severity="CRITICAL" size="sm" />}
                  {review.high_count > 0 && <SeverityBadge severity="HIGH" size="sm" />}
                  {review.medium_count > 0 && <SeverityBadge severity="MEDIUM" size="sm" />}
                  {review.total_comments === 0 && (
                    <span className="flex items-center gap-1 text-xs text-emerald-400 font-medium">
                      <CheckCircle size={11} /> Clean
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-3 text-xs text-slate-500">
                  <span className="flex items-center gap-1">
                    <Clock size={10} />
                    {review.created_at
                      ? formatDistanceToNow(new Date(review.created_at), { addSuffix: true })
                      : '-'}
                  </span>
                  <span>·</span>
                  <span>{review.total_comments ?? 0} comments</span>
                  {review.model_used && (
                    <>
                      <span>·</span>
                      <span className="font-mono">{review.model_used}</span>
                    </>
                  )}
                </div>
              </div>

              {/* 'skipped' reads as slate, not red: an oversized diff the
                  backend declined is a deliberate non-result, and colouring it
                  like a failure sends people hunting for a bug. */}
              <span className={`text-xs px-2.5 py-1 rounded-full flex-shrink-0 ${
                review.status === 'complete'
                  ? 'bg-emerald-500/10 text-emerald-400'
                  : review.status === 'pending' || review.status === 'running'
                  ? 'bg-yellow-500/10 text-yellow-400'
                  : review.status === 'skipped'
                  ? 'bg-slate-500/10 text-slate-400'
                  : 'bg-red-500/10 text-red-400'
              }`}>
                {review.status}
              </span>

              <ChevronRight size={14} className="text-slate-600 group-hover:text-slate-400 flex-shrink-0" />
            </button>
          ))}
        </div>
      )}

      {/* PR list */}
      {(prs as any[]).length > 0 && (
        <div>
          <h2 className="text-base font-semibold text-slate-200 mb-3">Pull Requests</h2>
          <div className="card divide-y divide-slate-800/60 p-0 overflow-hidden">
            {(prs as any[]).map((pr) => (
              <div key={pr.id} className="flex items-center gap-4 px-6 py-4">
                <GitPullRequest size={14} className="text-brand-400 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-slate-200 font-medium truncate">{pr.title ?? `PR #${pr.github_pr_number}`}</p>
                  <p className="text-xs text-slate-500">{pr.author} · {pr.base_branch}</p>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded-full ${
                  pr.status === 'open' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-700 text-slate-400'
                }`}>{pr.status}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
