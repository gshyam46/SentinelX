import React from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, History, Settings, FileText, User } from 'lucide-react';

const Layout = () => {
  const location = useLocation();

  const isActive = (path) => location.pathname === path ? 'active' : '';

  return (
    <div className="app-container">
      <aside className="sidebar glass">
        <div className="logo">
          <div className="logo-icon">
            <Shield size={20} color="#fff" />
          </div>
          SentinelX
        </div>

        <nav className="nav-links" style={{ flex: 1, marginTop: '20px' }}>
          <Link to="/" className={`nav-link ${isActive('/')}`}>
            <LayoutDashboard size={20} /> Dashboard
          </Link>
          <Link to="/scans" className={`nav-link ${isActive('/scans')}`}>
            <History size={20} /> Scan History
          </Link>
          <Link to="/reports" className={`nav-link ${isActive('/reports')}`}>
            <FileText size={20} /> Reports
          </Link>
          <Link to="/settings" className={`nav-link ${isActive('/settings')}`}>
            <Settings size={20} /> Settings
          </Link>
        </nav>

        <div className="user-profile glass" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px', marginTop: 'auto' }}>
          <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: 'var(--primary)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <User color="#0a0e17" />
          </div>
          <div>
            <div style={{ fontWeight: 600, fontSize: '14px' }}>Demo User</div>
            <div style={{ color: 'var(--primary)', fontSize: '12px' }}>Pro Tier</div>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="header">
          <div>
            <h1 className="title">Security Operations Center</h1>
            <p className="subtitle">Real-time reconnaissance and vulnerability intelligence.</p>
          </div>
          <div style={{ display: 'flex', gap: '16px' }}>
            <button className="btn btn-sm">Documentation</button>
            <div className="glass" style={{ padding: '8px 16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div className="status-dot complete"></div>
              <span>System Online</span>
            </div>
          </div>
        </header>

        <Outlet />
      </main>
    </div>
  );
};

export default Layout;
