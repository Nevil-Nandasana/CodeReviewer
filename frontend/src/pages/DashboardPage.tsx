import { useQuery } from '@tanstack/react-query'
import { analyticsApi } from '@/api/client'
import MetricCard from '@/components/shared/MetricCard'
import LoadingSpinner from '@/components/shared/LoadingSpinner'
import SeverityBadge from '@/components/shared/SeverityBadge'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { Shield, GitPullRequest, Star, TrendingUp, Clock, ChevronRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { formatDistanceToNow } from 'date-fns'

export default function DashboardPage() {
  const navigate = useNavigate()
  const { data: summary, isLoading } = useQuery({
    queryKey: ['dashboard-summary'],
    queryFn: () => analyticsApi.dashboard().then((r) => r.data),
    refetchInterval: 60_000,
  })
  const { data: activity } = useQuery({
    queryKey: ['recent-activity'],
    queryFn: () => analyticsApi.recentActivity(10).then((r) => r.data),
  })
  const { data: chartData } = useQuery({
    queryKey: ['reviews-per-day'],
    queryFn: () => analyticsApi.reviewsPerDay(14).then((r) => r.data),
  })

  if (isLoading) return <LoadingSpinner label="Loading dashboard…" />

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Dashboard</h1>
          <p className="text-slate-500 text-sm mt-0.5">AI-powered code review intelligence</p>
        </div>
        <div className="flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 rounded-full px-4 py-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-xs font-medium text-emerald-400">System Online</span>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard label="Total PRs Reviewed" value={summary?.total_prs_reviewed ?? 0} icon={<GitPullRequest size={16} />} sub="All time" />
        <MetricCard label="Critical + High Open" value={(summary?.critical_open ?? 0) + (summary?.high_open ?? 0)} icon={<Shield size={16} />} color="text-red-400" sub={`${summary?.critical_open ?? 0} critical · ${summary?.high_open ?? 0} high`} />
        <MetricCard label="Avg Quality Score" value={summary?.avg_quality_score != null ? `${summary.avg_quality_score}/100` : 'N/A'} icon={<Star size={16} />} color="text-yellow-400" sub="Across all files" />
        <MetricCard label="Reviews This Week" value={summary?.reviews_this_week ?? 0} icon={<TrendingUp size={16} />} color="text-emerald-400" sub="Last 7 days" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        <div className="card xl:col-span-3">
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-base font-semibold text-slate-200">Reviews per day</h2>
            <span className="text-xs text-slate-500">Last 14 days</span>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={chartData ?? []} barSize={18}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#64748b' }} tickFormatter={(d) => d.slice(5)} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} name="Reviews" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card xl:col-span-2">
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-base font-semibold text-slate-200">Recent Reviews</h2>
            <button onClick={() => navigate('/reviews')} className="text-xs text-brand-400 hover:text-brand-300 flex items-center gap-1">
              View all <ChevronRight size={12} />
            </button>
          </div>
          <div className="space-y-1">
            {!activity?.length && <p className="text-sm text-slate-600 text-center py-8">No reviews yet. Push a PR!</p>}
            {activity?.map((r: any) => (
              <button key={r.id} onClick={() => navigate(`/reviews/${r.id}`)} className="w-full text-left flex items-center gap-3 p-3 rounded-lg hover:bg-surface-800 transition-colors group">
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${r.critical > 0 ? 'bg-red-500' : r.high > 0 ? 'bg-orange-500' : 'bg-emerald-500'}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {r.critical > 0 && <SeverityBadge severity="CRITICAL" size="sm" />}
                    {r.high > 0 && <SeverityBadge severity="HIGH" size="sm" />}
                    {r.total === 0 && <span className="text-xs text-emerald-400 font-medium">Clean ✓</span>}
                  </div>
                  <p className="text-xs text-slate-500 mt-1 flex items-center gap-1">
                    <Clock size={10} />
                    {r.created_at ? formatDistanceToNow(new Date(r.created_at), { addSuffix: true }) : '-'}
                    <span className="text-slate-600">· {r.total} comments</span>
                  </p>
                </div>
                <ChevronRight size={14} className="text-slate-600 group-hover:text-slate-400 flex-shrink-0" />
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
