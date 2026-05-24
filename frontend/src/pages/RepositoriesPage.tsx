import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { reposApi } from '@/api/client'
import LoadingSpinner from '@/components/shared/LoadingSpinner'
import { GitBranch, Plus, ToggleLeft, ToggleRight, Shield, GitPullRequest, AlertTriangle, ExternalLink } from 'lucide-react'
import type { Repository } from '@/types'

function RepoCard({ repo }: { repo: Repository }) {
  const qc = useQueryClient()
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => reposApi.update(repo.id, { review_enabled: enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['repos'] }),
  })
  const { data: stats } = useQuery({ queryKey: ['repo-stats', repo.id], queryFn: () => reposApi.stats(repo.id).then(r => r.data) })

  return (
    <div className="card-hover group">
      <div className="flex items-start justify-between gap-3 mb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-brand-600/10 border border-brand-600/20 flex items-center justify-center">
            <GitBranch size={16} className="text-brand-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-200">{repo.name}</h3>
            <p className="text-xs text-slate-500">{repo.owner}</p>
          </div>
        </div>
        <button
          onClick={() => toggle.mutate(!repo.review_enabled)}
          className="text-slate-500 hover:text-brand-400 transition-colors"
          title={repo.review_enabled ? 'Disable reviews' : 'Enable reviews'}
        >
          {repo.review_enabled
            ? <ToggleRight size={22} className="text-brand-500" />
            : <ToggleLeft size={22} />
          }
        </button>
      </div>

      <div className="flex items-center gap-2 flex-wrap mb-4">
        {repo.language && (
          <span className="text-xs bg-surface-800 text-slate-400 border border-slate-700 px-2 py-0.5 rounded-full">{repo.language}</span>
        )}
        <span className={`text-xs px-2 py-0.5 rounded-full ${repo.review_enabled ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-700 text-slate-500'}`}>
          {repo.review_enabled ? 'Reviews ON' : 'Reviews OFF'}
        </span>
      </div>

      <div className="grid grid-cols-3 gap-2 bg-surface-800/50 rounded-lg p-3">
        <div className="text-center">
          <div className="flex items-center justify-center gap-1 mb-0.5">
            <GitPullRequest size={11} className="text-slate-500" />
            <span className="text-base font-bold text-slate-200">{stats?.total_reviews ?? '-'}</span>
          </div>
          <p className="text-xs text-slate-600">Reviews</p>
        </div>
        <div className="text-center">
          <div className="flex items-center justify-center gap-1 mb-0.5">
            <AlertTriangle size={11} className="text-orange-500" />
            <span className="text-base font-bold text-orange-400">{stats?.open_vulnerabilities ?? '-'}</span>
          </div>
          <p className="text-xs text-slate-600">Open Vulns</p>
        </div>
        <div className="text-center">
          <div className="flex items-center justify-center gap-1 mb-0.5">
            <Shield size={11} className="text-red-500" />
            <span className="text-base font-bold text-red-400">{stats?.critical_vulnerabilities ?? '-'}</span>
          </div>
          <p className="text-xs text-slate-600">Critical</p>
        </div>
      </div>

      <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-800">
        <p className="text-xs text-slate-600">{new Date(repo.created_at).toLocaleDateString()}</p>
        <a
          href={`https://github.com/${repo.full_name}`}
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-1 text-xs text-slate-500 hover:text-brand-400 transition-colors"
        >
          View on GitHub <ExternalLink size={10} />
        </a>
      </div>
    </div>
  )
}

export default function RepositoriesPage() {
  const [showInstallBanner, setShowInstallBanner] = useState(false)
  const { data: repos = [], isLoading } = useQuery({
    queryKey: ['repos'],
    queryFn: () => reposApi.list().then((r) => r.data),
  })

  const handleConnectRepo = () => {
    setShowInstallBanner(true)
    // Opens the GitHub App installation page
    window.open('https://github.com/apps/codereviewer-ai/installations/new', '_blank')
  }

  if (isLoading) return <LoadingSpinner label="Loading repositories…" />

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
            <GitBranch size={24} className="text-brand-400" /> Repositories
          </h1>
          <p className="text-slate-500 text-sm mt-0.5">Manage connected GitHub repositories</p>
        </div>
        <button onClick={handleConnectRepo} className="btn-primary flex items-center gap-2">
          <Plus size={16} /> Connect Repo
        </button>
      </div>

      {showInstallBanner && (
        <div className="flex items-start gap-3 bg-brand-600/10 border border-brand-600/30 rounded-xl px-5 py-4">
          <GitBranch size={16} className="text-brand-400 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="text-sm font-medium text-brand-300">GitHub App Installation</p>
            <p className="text-xs text-slate-400 mt-1">
              A new tab has opened to install the CodeReviewer GitHub App. After installing it on your repositories,
              they will appear here automatically when a pull request is opened.
            </p>
          </div>
          <button onClick={() => setShowInstallBanner(false)} className="text-slate-500 hover:text-slate-300 text-xs">✕</button>
        </div>
      )}

      {repos.length === 0 ? (
        <div className="card text-center py-20">
          <GitBranch size={40} className="text-slate-700 mx-auto mb-4" />
          <h3 className="text-slate-400 font-semibold mb-2">No repositories connected</h3>
          <p className="text-slate-600 text-sm mb-6 max-w-sm mx-auto">
            Install the CodeReviewer GitHub App on your repositories to start automated code review.
          </p>
          <a
            href="https://github.com/apps/codereviewer-ai"
            target="_blank"
            rel="noreferrer"
            className="btn-primary inline-flex items-center gap-2"
          >
            <Plus size={15} /> Install GitHub App
          </a>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {(repos as Repository[]).map((repo) => (
            <RepoCard key={repo.id} repo={repo} />
          ))}
        </div>
      )}
    </div>
  )
}
