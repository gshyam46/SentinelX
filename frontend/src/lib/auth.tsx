/**
 * SentinelX — Auth Context
 * Provides current user + tier throughout the app.
 */
import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import axios from 'axios'
import { api } from './api'

interface User {
  id: string
  email: string
  full_name: string
  tier: 'free' | 'pro' | 'enterprise'
  scan_count: number
  is_active: boolean
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
    if (!token) { setIsLoading(false); return }
    try {
      const res = await axios.get<User>('/api/v1/auth/me', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setUser(res.data)
    } catch {
      localStorage.removeItem('sentinel_token')
      setUser(null)
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => { fetchMe() }, [fetchMe])

  const login = async (email: string, password: string) => {
    await api.login(email, password)
    await fetchMe()
  }

  const logout = () => {
    api.logout()
    setUser(null)
  }

  const isPro = user?.tier === 'pro' || user?.tier === 'enterprise'

  return (
    <AuthContext.Provider value={{ user, isPro, isLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
