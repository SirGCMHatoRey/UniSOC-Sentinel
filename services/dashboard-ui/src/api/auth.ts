import client from './client'
import { User } from '@/types'

interface LoginResponse {
  access_token: string
  refresh_token: string
  token_type: string
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const formData = new URLSearchParams()
  formData.append('username', username)
  formData.append('password', password)

  const response = await client.post<LoginResponse>('/auth/token', formData, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return response.data
}

export async function logout(): Promise<void> {
  await client.post('/auth/logout')
}

export async function refresh(): Promise<{ access_token: string }> {
  const refreshToken = localStorage.getItem('refresh_token')
  const response = await client.post<{ access_token: string }>('/auth/refresh', {
    refresh_token: refreshToken,
  })
  return response.data
}

export async function getMe(): Promise<User> {
  const response = await client.get<User>('/auth/me')
  return response.data
}
