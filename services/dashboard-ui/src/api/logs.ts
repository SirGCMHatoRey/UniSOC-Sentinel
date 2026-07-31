import client from './client'
import { ECSEvent, LogsQuery, PaginatedResponse } from '@/types'

export async function getLogs(query: LogsQuery = {}): Promise<PaginatedResponse<ECSEvent>> {
  const params = new URLSearchParams()
  if (query.q) params.set('q', query.q)
  if (query.dataset) params.set('dataset', query.dataset)
  if (query.severity_min !== undefined) params.set('severity_min', String(query.severity_min))
  if (query.from_ts) params.set('from_ts', query.from_ts)
  if (query.to_ts) params.set('to_ts', query.to_ts)
  if (query.source_ip) params.set('source_ip', query.source_ip)
  if (query.page !== undefined) params.set('page', String(query.page))
  if (query.size !== undefined) params.set('size', String(query.size))

  const response = await client.get<PaginatedResponse<ECSEvent>>(`/logs?${params.toString()}`)
  return response.data
}

export async function getLog(id: string): Promise<ECSEvent> {
  const response = await client.get<ECSEvent>(`/logs/${id}`)
  return response.data
}
