import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './lib/auth'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import ScanDetail from './pages/ScanDetail'
import Login from './pages/Login'

/** Redirect unauthenticated users to /login */
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth()

  // Still fetching /me — show nothing (avoids flash)
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen" style={{ background: '#0A0D14' }}>
        <div className="spin text-2xl" style={{ color: '#3B82F6' }}>⊙</div>
      </div>
    )
  }

  // No token / expired — send to login
  // NOTE: during development with no backend, comment out this redirect to
  // browse the UI without auth. Set VITE_SKIP_AUTH=true in .env to skip it.
  const skipAuth = import.meta.env.VITE_SKIP_AUTH === 'true'
  if (!skipAuth && !user) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public */}
          <Route path="/login"    element={<Login />} />
          <Route path="/register" element={<Login />} />  {/* Reuse Login until Register page added */}

          {/* Protected shell */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index            element={<Dashboard />} />
            <Route path="scans"     element={<Dashboard />} />
            <Route path="scans/:scanId" element={<ScanDetail />} />
            <Route path="reports"   element={<Dashboard />} />
            <Route path="settings"  element={<Dashboard />} />
          </Route>

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}

export default App
