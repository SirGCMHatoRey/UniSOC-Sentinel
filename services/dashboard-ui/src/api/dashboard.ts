import client from './client'
import {
  DashboardStats,
  TopIP,
  FirewallDataPoint,
  GeoPoint,
  TimeSeriesPoint,
  VPNSession,
  WirelessEvent,
  ThreatIntelMatch,
  SystemHealth,
} from '@/types'

export async function getStats(): Promise<DashboardStats> {
  const response = await client.get<DashboardStats>('/dashboard/stats')
  return response.data
}

export async function getTopIPs(): Promise<TopIP[]> {
  const response = await client.get<TopIP[]>('/dashboard/top-ips')
  return response.data
}

export async function getFirewallActivity(
  from_ts: string,
  to_ts: string
): Promise<FirewallDataPoint[]> {
  const response = await client.get<FirewallDataPoint[]>('/dashboard/firewall-activity', {
    params: { from_ts, to_ts },
  })
  return response.data
}

export async function getGeoMap(): Promise<GeoPoint[]> {
  const response = await client.get<GeoPoint[]>('/dashboard/geo-map')
  return response.data
}

export async function getBandwidth(from_ts: string, to_ts: string): Promise<TimeSeriesPoint[]> {
  const response = await client.get<TimeSeriesPoint[]>('/dashboard/bandwidth', {
    params: { from_ts, to_ts },
  })
  return response.data
}

export async function getVPNSessions(): Promise<VPNSession[]> {
  const response = await client.get<VPNSession[]>('/dashboard/vpn-sessions')
  return response.data
}

export async function getWirelessActivity(): Promise<WirelessEvent[]> {
  const response = await client.get<WirelessEvent[]>('/dashboard/wireless-activity')
  return response.data
}

export async function getThreatIntelMatches(): Promise<ThreatIntelMatch[]> {
  const response = await client.get<ThreatIntelMatch[]>('/dashboard/threat-intel-matches')
  return response.data
}

export async function getSystemHealth(): Promise<SystemHealth> {
  const response = await client.get<SystemHealth>('/dashboard/system-health')
  return response.data
}
