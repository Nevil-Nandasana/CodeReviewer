import { useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { reviewsApi } from '@/api/client'
import LoadingSpinner from '@/components/shared/LoadingSpinner'
import SeverityBadge from '@/components/shared/SeverityBadge'
import { FileCode, Copy, CheckCheck, ChevronDown, ChevronUp, AlertTriangle, Shield, Code2, Tag } from 'lucide-react'
import type { Review, ReviewComment, Severity } from '@/types'
import clsx from 'clsx'

function FileTree({ comments, selectedFile, onSelect }: {
  comments: ReviewComment[]
  selectedFile: string | null
  onSelect: (f: string) => void
}) {
  const files = Array.from(new Set(comments.map((c) => c.file_path)))
  const getWorstSeverity = (file: string): Severity => {
    const fc = comments.filter((c) => c.file_path === file)
    const order: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    for (const s of order) if (fc.some((c) => c.severity === s)) return s
    return 'INFO'
  }

  return (
    <div className="w-60 flex-shrink-0 border-r border-slate-800 overflow-y-auto">
      <div className="px-4 py-3 border-b border-slate-800">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Files Changed</p>
        <p className="text-xs text-slate-600 mt-0.5">{files.length} files</p>
      </div>
      <div className="py-2">
        {files.map((f) => (
          <button
            key={f}
            onClick={() => onSelect(f)}
            className={clsx(
              'w-full text-left flex items-center gap-2 px-4 py-2 transition-colors',
              selectedFile === f ? 'bg-brand-600/10 border-r-2 border-brand-500' : 'hover:bg-surface-800'
            )}
          >
            <FileCode size={13} className="text-slate-500 flex-shrink-0" />
            <span className="text-xs text-slate-300 truncate flex-1">{f.split('/').pop()}</span>
            <SeverityBadge severity={getWorstSeverity(f)} size="sm" />
          </button>
        ))}
      </div>
    </div>
  )
}

function DiffViewer({ comments, selectedFile }: { comments: ReviewComment[]; selectedFile: string | null }) {
  const fileComments = comments.filter((c) => c.file_path === selectedFile)

  return (
    <div className="flex-1 overflow-y-auto p-6">
      {!selectedFile ? (
        <div className="flex flex-col items-center justify-center h-64 text-slate-600">
          <FileCode size={40} className="mb-3" />
          <p className="text-sm">Select a file to view review comments</p>
        </div>
      ) : (
        <div className="space-y-3">
          <h3 className="text-sm font-mono text-slate-400 bg-surface-800 rounded-lg px-4 py-2.5 border border-slate-700">
            {selectedFile}
          </h3>
          {fileComments.length === 0 && (
            <div className="text-center py-12 text-slate-600 text-sm">No comments for this file</div>
          )}
          {fileComments.map((c) => (
            <CommentCard key={c.id} comment={c} />
          ))}
        </div>
      )}
    </div>
  )
}

function CommentCard({ comment }: { comment: ReviewComment }) {
  const [expanded, setExpanded] = useState(true)
  const [copied, setCopied] = useState(false)
  const qc = useQueryClient()

  const markFP = useMutation({
    mutationFn: () => reviewsApi.updateComment(comment.id, { is_false_positive: !comment.is_false_positive }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['review-comments'] }),
  })

  const copy = () => {
    if (comment.suggestion) {
      navigator.clipboard.writeText(comment.suggestion)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const BORDER: Record<Severity, string> = {
    CRITICAL: 'border-l-red-500', HIGH: 'border-l-orange-500',
    MEDIUM: 'border-l-yellow-500', LOW: 'border-l-blue-500', INFO: 'border-l-violet-500',
  }

  return (
    <div className={clsx('card border-l-2 animate-fade-in', BORDER[comment.severity], comment.is_false_positive && 'opacity-50')}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={comment.severity} />
          {comment.owasp_category && (
            <span className="text-xs bg-surface-800 text-slate-400 border border-slate-700 px-2 py-0.5 rounded-full flex items-center gap-1">
              <Shield size={10} /> {comment.owasp_category}
            </span>
          )}
          {comment.category && (
            <span className="text-xs bg-surface-800 text-slate-500 border border-slate-700 px-2 py-0.5 rounded-full flex items-center gap-1">
              <Tag size={10} /> {comment.category}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">
          {comment.line_number && (
            <span className="text-xs font-mono text-slate-500 bg-surface-800 px-2 py-0.5 rounded">L{comment.line_number}</span>
          )}
          <button onClick={() => setExpanded(!expanded)} className="btn-ghost p-1.5">
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      <h4 className="text-sm font-semibold text-slate-100 mt-2">{comment.title}</h4>

      {expanded && (
        <div className="mt-3 space-y-3">
          <p className="text-sm text-slate-300 leading-relaxed">{comment.explanation}</p>

          {comment.suggestion && (
            <div className="bg-surface-950 rounded-lg border border-slate-700 overflow-hidden">
              <div className="flex items-center justify-between px-3 py-2 bg-surface-800 border-b border-slate-700">
                <div className="flex items-center gap-2">
                  <Code2 size={12} className="text-slate-500" />
                  <span className="text-xs text-slate-400 font-medium">Suggested fix</span>
                </div>
                <button onClick={copy} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors">
                  {copied ? <CheckCheck size={12} className="text-emerald-400" /> : <Copy size={12} />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <pre className="p-3 text-xs text-slate-300 font-mono overflow-x-auto leading-relaxed">
                <code>{comment.suggestion}</code>
              </pre>
            </div>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button
              onClick={() => markFP.mutate()}
              className={clsx(
                'text-xs px-3 py-1.5 rounded-lg border transition-colors',
                comment.is_false_positive
                  ? 'bg-slate-700 text-slate-300 border-slate-600'
                  : 'text-slate-500 border-slate-700 hover:border-slate-600 hover:text-slate-300'
              )}
            >
              {comment.is_false_positive ? '↩ Restore' : 'Mark false positive'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default function PRReviewPage() {
  const { reviewId } = useParams<{ reviewId: string }>()
  const [selectedFile, setSelectedFile] = useState<string | null>(null)

  const { data: review, isLoading: revLoading } = useQuery<Review>({
    queryKey: ['review', reviewId],
    queryFn: () => reviewsApi.get(reviewId!).then((r) => r.data),
    enabled: !!reviewId,
  })

  // React Query v5 removed the `onSuccess` callback from useQuery. Deriving the
  // default selection in an effect is also the correct shape regardless of
  // version: the previous code called setSelectedFile during render, which is a
  // render-phase state update and re-renders on every pass until it settles.
  const { data: comments = [], isLoading: comLoading } = useQuery<ReviewComment[]>({
    queryKey: ['review-comments', reviewId],
    queryFn: () => reviewsApi.getComments(reviewId!).then((r) => r.data),
    enabled: !!reviewId,
  })

  const files = useMemo(
    () => Array.from(new Set(comments.map((c) => c.file_path))),
    [comments],
  )

  useEffect(() => {
    if (!selectedFile && files.length) setSelectedFile(files[0])
  }, [files, selectedFile])

  if (revLoading || comLoading) return <LoadingSpinner label="Loading review…" />

  return (
    <div className="flex flex-col h-screen">
      {/* Top bar */}
      <div className="flex items-center gap-4 px-6 py-3.5 border-b border-slate-800 bg-surface-950 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className={clsx('w-2 h-2 rounded-full', review?.status === 'complete' ? 'bg-emerald-500' : review?.status === 'running' ? 'bg-yellow-500 animate-pulse' : 'bg-slate-500')} />
          <span className="text-sm font-semibold text-slate-200">Review</span>
          <span className="text-xs font-mono text-slate-500">{reviewId?.slice(0, 8)}</span>
        </div>
        <div className="flex items-center gap-2 ml-auto">
          <SeverityBadge severity="CRITICAL" /><span className="text-xs text-slate-500">{review?.critical_count}</span>
          <SeverityBadge severity="HIGH" /><span className="text-xs text-slate-500">{review?.high_count}</span>
          <SeverityBadge severity="MEDIUM" /><span className="text-xs text-slate-500">{review?.medium_count}</span>
          <span className="text-xs text-slate-600 ml-2">Model: {review?.model_used}</span>
          {review?.processing_time_seconds && (
            <span className="text-xs text-slate-600">{review.processing_time_seconds.toFixed(1)}s</span>
          )}
        </div>
      </div>

      {/* Three-panel body */}
      <div className="flex flex-1 overflow-hidden">
        <FileTree comments={comments} selectedFile={selectedFile} onSelect={setSelectedFile} />
        <DiffViewer comments={comments} selectedFile={selectedFile} />
      </div>
    </div>
  )
}
