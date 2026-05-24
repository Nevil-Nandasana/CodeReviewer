import { useQuery } from '@tanstack/react-query'
import { qualityApi } from '@/api/client'
import MetricCard from '@/components/shared/MetricCard'
import LoadingSpinner from '@/components/shared/LoadingSpinner'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, BarChart, Bar } from 'recharts'
import { BarChart2, Zap, Code2, MessageSquare } from 'lucide-react'

export default function QualityPage() {
  const { data: trends, isLoading } = useQuery({ queryKey: ['q-trends'], queryFn: () => qualityApi.trends().then(r => r.data) })
  const { data: files } = useQuery({ queryKey: ['q-files'], queryFn: () => qualityApi.files().then(r => r.data) })
  const { data: issues } = useQuery({ queryKey: ['q-issues'], queryFn: () => qualityApi.issues().then(r => r.data) })
  const { data: metrics } = useQuery({ queryKey: ['q-metrics'], queryFn: () => qualityApi.metrics().then(r => r.data) })

  if (isLoading) return <LoadingSpinner label="Loading quality data…" />

  const avgScore = metrics?.length ? Math.round(metrics.reduce((a: number, m: any) => a + (m.overall_quality_score ?? 0), 0) / metrics.length) : null
  const avgComplexity = files?.length ? (files.reduce((a: number, f: any) => a + (f.cyclomatic_complexity ?? 0), 0) / files.length).toFixed(1) : null

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3"><BarChart2 size={24} className="text-brand-400" />Code Quality</h1>
        <p className="text-slate-500 text-sm mt-0.5">Cyclomatic complexity, function length, and quality trends</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard label="Avg Quality Score" value={avgScore != null ? `${avgScore}/100` : 'N/A'} color="text-brand-400" icon={<Zap size={16}/>} />
        <MetricCard label="Avg Complexity" value={avgComplexity ?? 'N/A'} color="text-yellow-400" icon={<Code2 size={16}/>} sub="Cyclomatic" />
        <MetricCard label="Files Analyzed" value={files?.length ?? 0} icon={<BarChart2 size={16}/>} sub="Changed files" />
        <MetricCard label="Quality Issues" value={issues?.reduce((a: number, i: any) => a + i.count, 0) ?? 0} icon={<MessageSquare size={16}/>} color="text-orange-400" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Quality trend */}
        <div className="card">
          <h2 className="text-base font-semibold text-slate-200 mb-4">Quality Score Trend</h2>
          {trends?.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={trends}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#64748b' }} tickFormatter={(d) => d ? new Date(d).toLocaleDateString('en', { month: 'short', day: 'numeric' }) : ''} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                <Line type="monotone" dataKey="score" stroke="#6366f1" strokeWidth={2} dot={false} name="Quality" />
              </LineChart>
            </ResponsiveContainer>
          ) : <p className="text-slate-600 text-sm text-center py-16">No quality data yet</p>}
        </div>

        {/* Common issues */}
        <div className="card">
          <h2 className="text-base font-semibold text-slate-200 mb-4">Common Quality Issues</h2>
          {issues?.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={issues?.slice(0,8)} layout="vertical" barSize={12}>
                <XAxis type="number" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="issue" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} width={160} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="count" fill="#f97316" radius={[0,4,4,0]} name="Count" />
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="text-slate-600 text-sm text-center py-16">No issues data yet</p>}
        </div>
      </div>

      {/* Files complexity table */}
      <div className="card">
        <h2 className="text-base font-semibold text-slate-200 mb-4">File Complexity Analysis</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-slate-800">
              {['File','Language','Complexity','LOC','Avg Fn Length','Quality Score'].map((h) => (
                <th key={h} className="text-left text-xs font-medium text-slate-500 pb-3 pr-4">{h}</th>
              ))}
            </tr></thead>
            <tbody className="divide-y divide-slate-800/50">
              {!files?.length && <tr><td colSpan={6} className="text-center py-10 text-slate-600 text-sm">No file data yet</td></tr>}
              {files?.map((f: any) => (
                <tr key={f.file_path} className="hover:bg-surface-800/30 transition-colors">
                  <td className="py-3 pr-4 text-xs font-mono text-slate-300 max-w-48 truncate">{f.file_path?.split('/').pop()}</td>
                  <td className="py-3 pr-4 text-xs text-slate-500 capitalize">{f.language}</td>
                  <td className="py-3 pr-4">
                    <span className={`text-xs font-semibold ${(f.cyclomatic_complexity ?? 0) > 10 ? 'text-red-400' : (f.cyclomatic_complexity ?? 0) > 5 ? 'text-yellow-400' : 'text-emerald-400'}`}>
                      {f.cyclomatic_complexity?.toFixed(1) ?? '-'}
                    </span>
                  </td>
                  <td className="py-3 pr-4 text-xs text-slate-400">{f.lines_of_code ?? '-'}</td>
                  <td className="py-3 pr-4 text-xs text-slate-400">{f.avg_function_length?.toFixed(0) ?? '-'}</td>
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-surface-800 rounded-full overflow-hidden">
                        <div className="h-full rounded-full bg-brand-500" style={{ width: `${f.overall_quality_score ?? 0}%` }} />
                      </div>
                      <span className="text-xs text-slate-400">{f.overall_quality_score?.toFixed(0) ?? '-'}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
