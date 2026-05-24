import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Shield, GitPullRequest, BarChart2,
  GitBranch, LogOut, Cpu, ChevronRight, Bell
} from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { useQuery } from '@tanstack/react-query'
import { modelApi } from '@/api/client'
import clsx from 'clsx'

const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/reviews', icon: GitPullRequest, label: 'PR Reviews' },
  { to: '/security', icon: Shield, label: 'Security' },
  { to: '/quality', icon: BarChart2, label: 'Code Quality' },
  { to: '/repositories', icon: GitBranch, label: 'Repositories' },
]

export default function Layout() {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()

  const { data: modelStatus } = useQuery({
    queryKey: ['model-status'],
    queryFn: () => modelApi.status().then((r) => r.data),
    refetchInterval: 30_000,
  })

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="flex h-screen overflow-hidden bg-surface-950">
      {/* Sidebar */}
      <aside className="w-60 flex-shrink-0 flex flex-col border-r border-slate-800/60 bg-surface-950">
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5 border-b border-slate-800/60">
          <div className="w-8 h-8 rounded-lg bg-brand-600 flex items-center justify-center shadow-lg shadow-brand-600/30">
            <Shield size={16} className="text-white" />
          </div>
          <div>
            <span className="font-bold text-slate-100 text-base leading-none">CodeReviewer</span>
            <p className="text-xs text-slate-500 mt-0.5">AI Code Review</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => clsx(isActive ? 'sidebar-link-active' : 'sidebar-link')}
            >
              <Icon size={17} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Model status chip */}
        <div className="px-4 py-3 border-t border-slate-800/60">
          <div className="flex items-center gap-2.5 bg-surface-800/60 rounded-lg px-3 py-2.5">
            <Cpu size={14} className={modelStatus?.ready ? 'text-emerald-400' : 'text-slate-500'} />
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-slate-300 truncate">
                {modelStatus?.model ?? 'Loading…'}
              </p>
              <p className="text-xs text-slate-500">
                {modelStatus?.backend === 'local'
                  ? `${modelStatus?.vram_used_gb ?? '?'} GB VRAM`
                  : 'OpenAI API'}
              </p>
            </div>
            <div className={clsx(
              'w-1.5 h-1.5 rounded-full flex-shrink-0',
              modelStatus?.ready ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'
            )} />
          </div>
        </div>

        {/* User */}
        <div className="px-3 py-3 border-t border-slate-800/60">
          <div className="flex items-center gap-3 px-2 py-2">
            <div className="w-7 h-7 rounded-full bg-brand-600/20 border border-brand-600/40 flex items-center justify-center flex-shrink-0">
              <span className="text-xs font-semibold text-brand-400">
                {user?.username?.[0]?.toUpperCase() ?? 'U'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-slate-200 truncate">{user?.username}</p>
              <p className="text-xs text-slate-500 truncate">{user?.email}</p>
            </div>
            <button
              onClick={handleLogout}
              className="text-slate-500 hover:text-red-400 transition-colors p-1"
              title="Logout"
            >
              <LogOut size={14} />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <div className="page-enter">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
