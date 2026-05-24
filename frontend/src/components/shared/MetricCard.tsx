interface Props {
  label: string
  value: string | number
  sub?: string
  icon?: React.ReactNode
  trend?: 'up' | 'down' | 'neutral'
  color?: string
}

export default function MetricCard({ label, value, sub, icon, color = 'text-brand-400' }: Props) {
  return (
    <div className="metric-card animate-fade-in">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">{label}</p>
        {icon && <span className="text-slate-500">{icon}</span>}
      </div>
      <p className={`text-3xl font-bold ${color} leading-none mt-1`}>{value}</p>
      {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
    </div>
  )
}
