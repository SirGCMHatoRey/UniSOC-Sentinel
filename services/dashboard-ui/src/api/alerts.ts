import client from './client'
import { Alert, AlertsQuery, PaginatedResponse } from '@/types'

export async function getAlerts(query: AlertsQuery = {}): Promise<PaginatedResponse<Alert>> {
  const params = new URLSearchParams()
  if (query.severity) params.set('severity', query.severity)
  if (query.acknowledged !== undefined) params.set('acknowledged', String(query.acknowledged))
  if (query.from_ts) params.set('from_ts', query.from_ts)
  if (query.to_ts) params.set('to_ts', query.to_ts)
  if (query.page !== undefined) params.set('page', String(query.page))
  if (query.size !== undefined) params.set('size', String(query.size))

  const response = await client.get<PaginatedResponse<Alert>>(`/alerts?${params.toString()}`)
  return response.data
}

export async function getAlert(id: string): Promise<Alert> {
  const response = await client.get<Alert>(`/alerts/${id}`)
  return response.data
}

export async function acknowledgeAlert(id: string): Promise<Alert> {
  const response = await client.post<Alert>(`/alerts/${id}/acknowledge`)
  return response.data
}
