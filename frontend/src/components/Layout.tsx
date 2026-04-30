import React from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  Shield, LayoutDashboard, Search, FileText,
  Brain, LogOut, ChevronRight,
} from 'lucide-react'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { COLOR } from '../lib/theme'

const NAV = [
  { to: '/',        icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans',   icon: Search,          label: 'Scans'     },
  { to: '/reports', icon: FileText,        label: 'Reports'   },
  { to: '/llm',     icon: Brain,           label: 'LLM Security' },
]

export default function Layout() {
  const navigate = useNavigate()
  const { user, isPro } = useAuth()

  function handleLogout() {
    api.logout()
    navigate('/login')
  }

  return (
    <div className="flex min-h-screen" style={{ background: COLOR.bg.base }}>

      {/* Sidebar */}
      <aside
        className="flex flex-col fixed top-0 left-0 h-screen z-40"
        style={{
          width: 220,
          background: COLOR.bg.surface,
          borderRight: `1px solid ${COLOR.bg.border}`,
        }}
      >
        {/* Logo */}
        <div
          className="flex items-center gap-3 px-5 py-5"
          style={{ borderBottom: `1px solid ${COLOR.bg.border}` }}
        >
          <div
            className="flex items-center justify-center rounded-lg"
            style={{
              width: 32, height: 32,
              background: `linear-gradient(135deg, ${COLOR.green['500']} 0%, ${COLOR.green['300']} 100%)`,
              boxShadow: COLOR.green.glow,
            }}
          >
            <Shield size={17} color={COLOR.bg.base} strokeWidth={2.5} />
          </div>
          <div>
            <span className="font-bold text-sm tracking-wider" style={{ color: COLOR.text.primary }}>
              SENTINEL<span style={{ color: COLOR.accent }}>X</span>
            </span>
            <div className="text-xs" style={{ color: COLOR.text.muted }}>Security Intelligence</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
          <div className="mb-3 px-2">
            <span className="text-xs font-semibold uppercase tracking-widest" style={{ color: COLOR.text.muted }}>
              Platform
            </span>
          </div>
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
            >
              <Icon size={15} />
              <span className="flex-1">{label}</span>
              <ChevronRight size={11} style={{ opacity: 0.3 }} />
            </NavLink>
          ))}
        </nav>

        {/* User */}
        <div className="px-3 py-4 space-y-1" style={{ borderTop: `1px solid ${COLOR.bg.border}` }}>
          {user && (
            <div className="px-2 py-2 mb-1">
              <div className="flex items-center gap-2 mb-1">
                <span
                  className="text-xs px-2 py-0.5 rounded-full font-bold"
                  style={{
                    background: isPro ? 'rgba(46,165,95,0.12)' : 'rgba(74,109,130,0.1)',
                    color: isPro ? COLOR.accent : COLOR.slate['300'],
                    border: `1px solid ${isPro ? 'rgba(46,165,95,0.25)' : COLOR.bg.border}`,
                  }}
                >
                  {isPro ? 'PRO' : 'FREE'}
                </span>
              </div>
              <p className="text-xs mono truncate" style={{ color: COLOR.text.muted }} title={user.email}>
                {user.email}
              </p>
            </div>
          )}
          <button className="sidebar-link w-full" onClick={handleLogout} style={{ border: 'none', background: 'none', cursor: 'pointer' }}>
            <LogOut size={14} />
            <span>Sign out</span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto" style={{ marginLeft: 220, minHeight: '100vh' }}>
        <Outlet />
      </main>
    </div>
  )
}
