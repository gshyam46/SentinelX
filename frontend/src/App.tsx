import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './lib/auth'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import ScanDetail from './pages/ScanDetail'
import LLMSecurity from './pages/LLMSecurity'
import Auth from './pages/Auth'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen" style={{ background: '#080d0b', color: '#2ea55f' }}>
        <span className="spin" style={{ fontSize: 22 }}>⊙</span>
      </div>
    )
  }

  const skipAuth = import.meta.env.VITE_SKIP_AUTH === 'true'
  if (!skipAuth && !user) return <Navigate to="/login" replace />

  return <>{children}</>
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public */}
          <Route path="/login"    element={<Auth />} />
          <Route path="/register" element={<Auth />} />

          {/* Protected shell */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index                         element={<Dashboard />} />
            <Route path="scans"                  element={<Dashboard />} />
            <Route path="scans/:scanId"          element={<ScanDetail />} />
            <Route path="scans/:scanId/llm-security" element={<LLMSecurity />} />
            <Route path="reports"                element={<Dashboard />} />
            <Route path="settings"               element={<Dashboard />} />
            <Route path="llm"                    element={<Dashboard />} />
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
