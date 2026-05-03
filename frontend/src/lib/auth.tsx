/**
 * SentinelX — Auth Context
 * Provides current user + tier throughout the app.
 */
import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import axios from 'axios'
import { api, type TokenResponse } from './api'

interface User {
  id: string
  email: string
  full_name: string | null
  tier: string
  scan_count: number
  is_active: boolean
  created_at?: string
}

interface AuthCtx {
  user: User | null
  isPro: boolean
  isLoading: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthCtx>({
  user: null,
  isPro: false,
  isLoading: true,
  login: async () => {},
  logout: () => {},
})

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const fetchMe = useCallback(async () => {
    const token = localStorage.getItem('sentinel_token')
    if (!token) {
      setIsLoading(false)
      return
    }

    // Fast path: restore cached user object while /me is in-flight
    const cached = localStorage.getItem('sentinel_user')
    if (cached) {
      try {
        setUser(JSON.parse(cached))
      } catch {
        localStorage.removeItem('sentinel_user')
      }
    }

    try {
      const res = await axios.get<User>('/api/v1/auth/me', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setUser(res.data)
      localStorage.setItem('sentinel_user', JSON.stringify(res.data))
    } catch {
      // Token invalid/expired — clear everything
      localStorage.removeItem('sentinel_token')
      localStorage.removeItem('sentinel_user')
      setUser(null)
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchMe()
  }, [fetchMe])

  const login = async (email: string, password: string) => {
    // api.login stores token + user in localStorage
    const data: TokenResponse = await api.login(email, password)
    setUser(data.user)
    setIsLoading(false)
  }

  const logout = () => {
    api.logout()
    setUser(null)
  }

  // 'paid' is the DB value for pro-tier users; 'pro' and 'enterprise' are also pro.
  // In local dev, VITE_DEV_BYPASS_SECRET forces isPro=true so the UI reflects full access.
  const devBypass = !!import.meta.env.VITE_DEV_BYPASS_SECRET
  const isPro = devBypass || user?.tier === 'pro' || user?.tier === 'paid' || user?.tier === 'enterprise'

  return (
    <AuthContext.Provider value={{ user, isPro, isLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
