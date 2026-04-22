import React from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  Shield, LayoutDashboard, Search, FileText,
  Settings, LogOut, Bell, ChevronRight
} from 'lucide-react'
import { api } from '@/lib/api'

const NAV_ITEMS = [
  { to: '/',        icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans',   icon: Search,          label: 'Scans' },
  { to: '/reports', icon: FileText,        label: 'Reports' },
  { to: '/settings',icon: Settings,        label: 'Settings' },
]

export default function Layout() {
  const navigate = useNavigate()

  function handleLogout() {
    api.logout()
    navigate('/login')
  }

  return (
    <div className="flex min-h-screen bg-grid" style={{ background: '#0A0D14' }}>
      {/* Ambient glows */}
      <div
        className="fixed pointer-events-none"
        style={{
          top: '-15%', left: '-8%',
          width: '40vw', height: '40vw',
          background: 'radial-gradient(circle, rgba(59,130,246,0.06) 0%, transparent 65%)',
          borderRadius: '50%',
        }}
      />
      <div
        className="fixed pointer-events-none"
        style={{
          bottom: '-15%', right: '-8%',
          width: '35vw', height: '35vw',
          background: 'radial-gradient(circle, rgba(139,92,246,0.05) 0%, transparent 65%)',
          borderRadius: '50%',
        }}
      />

      {/* Sidebar */}
      <aside
        className="flex flex-col fixed top-0 left-0 h-screen z-40"
        style={{
          width: 220,
          background: 'rgba(10,13,20,0.95)',
          borderRight: '1px solid #1F2937',
          backdropFilter: 'blur(20px)',
        }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5" style={{ borderBottom: '1px solid #1F2937' }}>
          <div
            className="flex items-center justify-center rounded-lg"
            style={{
              width: 32, height: 32,
              background: 'linear-gradient(135deg, #3B82F6 0%, #6366F1 100%)',
              boxShadow: '0 0 16px rgba(59,130,246,0.4)',
            }}
          >
            <Shield size={17} color="#fff" strokeWidth={2.5} />
          </div>
          <div>
            <span className="font-bold text-sm tracking-wider" style={{ color: '#F9FAFB' }}>
              SENTINEL<span style={{ color: '#3B82F6' }}>X</span>
            </span>
            <div className="text-xs" style={{ color: '#4B5563' }}>Security Intelligence</div>
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
              className={({ isActive }) =>
                `sidebar-link ${isActive ? 'active' : ''}`
              }
            >
              <Icon size={15} />
              <span className="flex-1">{label}</span>
              <ChevronRight size={12} style={{ opacity: 0.3 }} />
            </NavLink>
          ))}
        </nav>

        {/* User bar */}
        <div className="px-3 py-4 space-y-1" style={{ borderTop: '1px solid #1F2937' }}>
          <button className="sidebar-link w-full">
            <Bell size={15} />
            <span className="flex-1">Alerts</span>
            <span
              className="text-xs px-1.5 py-0.5 rounded-full font-mono"
              style={{ background: 'rgba(239,68,68,0.15)', color: '#EF4444' }}
            >
              3
            </span>
          </button>
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
