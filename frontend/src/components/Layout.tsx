import React from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  Shield, LayoutDashboard, Search, FileText,
  Settings, LogOut, ChevronRight,
} from 'lucide-react'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { ACCENT, BG } from '@/lib/theme'

const NAV_ITEMS = [
  { to: '/',         icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans',    icon: Search,          label: 'Scans' },
  { to: '/reports',  icon: FileText,        label: 'Reports' },
  { to: '/settings', icon: Settings,        label: 'Settings' },
]

export default function Layout() {
  const navigate = useNavigate()
  const { user, isPro } = useAuth()

  function handleLogout() {
    api.logout()
    navigate('/login')
  }

  return (
    <div className="flex min-h-screen bg-grid" style={{ background: BG.base }}>
      {/* Ambient glows */}
      <div
        className="fixed pointer-events-none"
        style={{
          top: '-15%', left: '-8%',
          width: '40vw', height: '40vw',
          background: 'radial-gradient(circle, rgba(0,212,255,0.04) 0%, transparent 65%)',
          borderRadius: '50%',
        }}
      />
      <div
        className="fixed pointer-events-none"
        style={{
          bottom: '-15%', right: '-8%',
          width: '35vw', height: '35vw',
          background: 'radial-gradient(circle, rgba(139,92,246,0.04) 0%, transparent 65%)',
          borderRadius: '50%',
        }}
      />

      {/* Sidebar */}
      <aside
        className="flex flex-col fixed top-0 left-0 h-screen z-40"
        style={{
          width: 220,
          background: 'rgba(10,14,26,0.97)',
          borderRight: `1px solid ${BG.border}`,
          backdropFilter: 'blur(20px)',
        }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5" style={{ borderBottom: `1px solid ${BG.border}` }}>
          <div
            className="flex items-center justify-center rounded-lg"
            style={{
              width: 32, height: 32,
              background: `linear-gradient(135deg, ${ACCENT} 0%, #0090b3 100%)`,
              boxShadow: `0 0 16px rgba(0,212,255,0.35)`,
            }}
          >
            <Shield size={17} color="#0a0e1a" strokeWidth={2.5} />
          </div>
          <div>
            <span className="font-bold text-sm tracking-wider" style={{ color: '#f9fafb' }}>
              SENTINEL<span style={{ color: ACCENT }}>X</span>
            </span>
            <div className="text-xs" style={{ color: '#4b5563' }}>Security Intelligence</div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <div className="mb-3">
            <span className="px-2 text-xs font-semibold uppercase tracking-widest" style={{ color: '#374151' }}>
              Platform
            </span>
          </div>
          {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
            >
              <Icon size={15} />
              <span className="flex-1">{label}</span>
              <ChevronRight size={12} style={{ opacity: 0.3 }} />
            </NavLink>
          ))}
        </nav>

        {/* User bar */}
        <div className="px-3 py-4 space-y-1" style={{ borderTop: `1px solid ${BG.border}` }}>
          {user && (
            <div className="px-2 py-2 mb-2">
              <div className="flex items-center gap-2">
                <span
                  className="text-xs px-1.5 py-0.5 rounded font-bold"
                  style={{
                    background: isPro ? 'rgba(0,212,255,0.12)' : 'rgba(107,114,128,0.12)',
                    color: isPro ? ACCENT : '#6b7280',
                    border: `1px solid ${isPro ? 'rgba(0,212,255,0.25)' : 'rgba(107,114,128,0.25)'}`,
                  }}
                >
                  {isPro ? 'PRO' : 'FREE'}
                </span>
              </div>
              <p className="text-xs font-mono mt-1 truncate" style={{ color: '#6b7280' }} title={user.email}>
                {user.email}
              </p>
            </div>
          )}
          <button className="sidebar-link w-full" onClick={handleLogout}>
            <LogOut size={15} />
            <span>Sign out</span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main
        className="flex-1 overflow-y-auto"
        style={{ marginLeft: 220, minHeight: '100vh' }}
      >
        <Outlet />
      </main>
    </div>
  )
}
