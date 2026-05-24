import { useQuery } from '@tanstack/react-query'
import { securityApi } from '@/api/client'
import MetricCard from '@/components/shared/MetricCard'
import LoadingSpinner from '@/components/shared/LoadingSpinner'
import SeverityBadge from '@/components/shared/SeverityBadge'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { Shield, CheckCircle, AlertTriangle, FileWarning } from 'lucide-react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import type { Vulnerability } from '@/types'

const COLORS = ['#ef4444','#f97316','#eab308','#22c55e','#3b82f6','#8b5cf6','#ec4899']

export default function SecurityPage() {
  const [sevFilter, setSevFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('open')
  const qc = useQueryClient()

  const { data: summary, isLoading } = useQuery({ queryKey: ['sec-summary'], queryFn: () => securityApi.summary().then(r => r.data) })
  const { data: owasp } = useQuery({ queryKey: ['owasp'], queryFn: () => securityApi.owaspBreakdown().then(r => r.data) })
  const { data: heatmap } = useQuery({ queryKey: ['heatmap'], queryFn: () => securityApi.fileHeatmap().then(r => r.data) })
  const { data: vulns = [] } = useQuery({
    queryKey: ['vulns', sevFilter, statusFilter],
    queryFn: () => securityApi.listVulns({
      severity: sevFilter !== 'all' ? sevFilter : undefined,
      status: statusFilter !== 'all' ? statusFilter : undefined,
    }).then(r => r.data),
  })

  const resolve = useMutation({
    mutationFn: (id: string) => securityApi.updateVuln(id, { status: 'resolved' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['vulns'] }); qc.invalidateQueries({ queryKey: ['sec-summary'] }) },
  })

  if (isLoading) return <LoadingSpinner label="Loading security data…" />

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3"><Shield size={24} className="text-red-400" />Security Intelligence</h1>
        <p className="text-slate-500 text-sm mt-0.5">OWASP Top 10 vulnerability tracking</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard label="Open Critical" value={summary?.critical_open ?? 0} color="text-red-400" icon={<AlertTriangle size={16}/>} />
        <MetricCard label="Open High" value={summary?.high_open ?? 0} color="text-orange-400" icon={<AlertTriangle size={16}/>} />
        <MetricCard label="Open Medium" value={summary?.medium_open ?? 0} color="text-yellow-400" icon={<FileWarning size={16}/>} />
        <MetricCard label="Resolved" value={summary?.total_resolved ?? 0} color="text-emerald-400" icon={<CheckCircle size={16}/>} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-base font-semibold text-slate-200 mb-4">OWASP Breakdown</h2>
          {owasp?.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={owasp} layout="vertical" barSize={14}>
                <XAxis type="number" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="owasp_category" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} width={150} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="count" radius={[0,4,4,0]}>{owasp.map((_: any, i: number) => <Cell key={i} fill={COLORS[i%COLORS.length]} />)}</Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="text-slate-600 text-sm text-center py-12">No vulnerability data yet</p>}
        </div>

        <div className="card">
          <h2 className="text-base font-semibold text-slate-200 mb-4">Most Vulnerable Files</h2>
          <div className="space-y-2.5">
            {!heatmap?.length && <p className="text-slate-600 text-sm text-center py-12">No data yet</p>}
            {heatmap?.slice(0, 8).map((item: any, i: number) => (
              <div key={i} className="flex items-center gap-3">
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-mono text-slate-300 truncate">{item.file_path?.split('/').pop()}</p>
                  <p className="text-xs text-slate-600 truncate">{item.file_path}</p>
                </div>
                <span className="text-xs font-semibold text-red-400 flex-shrink-0">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
          <h2 className="text-base font-semibold text-slate-200">Vulnerabilities</h2>
          <div className="flex items-center gap-2">
            {(['all','CRITICAL','HIGH','MEDIUM','LOW'] as const).map((s) => (
              <button key={s} onClick={() => setSevFilter(s)} className={`text-xs px-2.5 py-1 rounded-lg border transition-colors ${sevFilter === s ? 'bg-brand-600/20 border-brand-600/50 text-brand-300' : 'border-slate-700 text-slate-500 hover:text-slate-300'}`}>{s}</button>
            ))}
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="bg-surface-800 border border-slate-700 text-slate-300 text-xs rounded-lg px-2 py-1 ml-2">
              <option value="open">Open</option>
              <option value="resolved">Resolved</option>
              <option value="all">All</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-slate-800">
              {['Severity','Type','File','Line','OWASP','Status',''].map((h) => (
                <th key={h} className="text-left text-xs font-medium text-slate-500 pb-3 pr-4">{h}</th>
              ))}
            </tr></thead>
            <tbody className="divide-y divide-slate-800/50">
              {vulns.length === 0 && <tr><td colSpan={7} className="text-center py-10 text-slate-600 text-sm">No vulnerabilities ✓</td></tr>}
              {(vulns as Vulnerability[]).map((v) => (
                <tr key={v.id} className="hover:bg-surface-800/30 transition-colors">
                  <td className="py-3 pr-4"><SeverityBadge severity={v.severity} size="sm" /></td>
                  <td className="py-3 pr-4 text-xs text-slate-300">{v.vuln_type?.replace(/_/g,' ')}</td>
                  <td className="py-3 pr-4 text-xs font-mono text-slate-400 max-w-28 truncate">{v.file_path?.split('/').pop()}</td>
                  <td className="py-3 pr-4 text-xs text-slate-500">{v.line_number ?? '-'}</td>
                  <td className="py-3 pr-4 text-xs text-slate-500 max-w-32 truncate">{v.owasp_category ?? '-'}</td>
                  <td className="py-3 pr-4">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${v.status === 'open' ? 'bg-red-500/10 text-red-400' : 'bg-emerald-500/10 text-emerald-400'}`}>{v.status}</span>
                  </td>
                  <td className="py-3">
                    {v.status === 'open' && (
                      <button onClick={() => resolve.mutate(v.id)} className="text-xs text-brand-400 hover:text-brand-300">Resolve</button>
                    )}
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
