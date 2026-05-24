import type { Severity } from '@/types'
import clsx from 'clsx'

interface Props {
  severity: Severity
  size?: 'sm' | 'md'
}

const LABELS: Record<Severity, string> = {
  CRITICAL: '🔴 Critical',
  HIGH: '🟠 High',
  MEDIUM: '🟡 Medium',
  LOW: '🔵 Low',
  INFO: '⚪ Info',
}

const CLASSES: Record<Severity, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
  INFO: 'badge-info',
}

export default function SeverityBadge({ severity, size = 'md' }: Props) {
  return (
    <span className={clsx(CLASSES[severity], size === 'sm' && 'text-[10px] px-1.5 py-0')}>
      {LABELS[severity]}
    </span>
  )
}
