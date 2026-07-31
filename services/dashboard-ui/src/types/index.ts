export interface User {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

export interface ECSEvent {
  '@timestamp': string;
  event: {
    id: string;
    kind: string;
    category: string[];
    type: string[];
    dataset: string;
    severity: number;
    outcome: string;
  };
  source: {
    ip: string | null;
    port: number | null;
    mac: string | null;
    geo: {
      country_iso_code: string;
      country_name: string;
      city_name: string;
      location: { lat: number; lon: number } | null;
    } | null;
    threat_intel: {
      matched: boolean;
      feed: string | null;
      score: number;
    } | null;
  };
  destination: {
    ip: string | null;
    port: number | null;
  };
  network: {
    protocol: string | null;
    direction: string;
    bytes: number;
    packets: number;
  };
  host: {
    hostname: string | null;
  };
  user: {
    name: string | null;
  };
  message: string;
  raw_message: string;
  tags: string[];
}

export interface Alert {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  created_at: string;
  acknowledged: boolean;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  event_count: number;
  metadata: Record<string, unknown>;
}

export interface DashboardStats {
  total_events: number;
  total_alerts: number;
  blocked_connections: number;
  auth_failures: number;
  active_vpn_sessions: number;
  threat_intel_matches: number;
}

export interface TopIP {
  ip: string;
  count: number;
  country: string;
  country_code: string;
}

export interface TimeSeriesPoint {
  timestamp: string;
  value: number;
}

export interface GeoPoint {
  lat: number;
  lon: number;
  count: number;
  country: string;
}

export interface PaginatedResponse<T> {
  total: number;
  page: number;
  size: number;
  hits: T[];
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  is_active: boolean;
}

export type LogsQuery = {
  q?: string;
  dataset?: string;
  severity_min?: number;
  from_ts?: string;
  to_ts?: string;
  source_ip?: string;
  page?: number;
  size?: number;
};

export type AlertsQuery = {
  severity?: string;
  acknowledged?: boolean;
  from_ts?: string;
  to_ts?: string;
  page?: number;
  size?: number;
};

export interface FirewallDataPoint {
  timestamp: string;
  allow: number;
  deny: number;
}

export interface VPNSession {
  user: string;
  source_ip: string;
  country: string;
  connected_at: string;
}

export interface WirelessEvent {
  timestamp: string;
  mac: string;
  ssid: string;
  event_type: string;
  hostname: string | null;
}

export interface ThreatIntelMatch {
  timestamp: string;
  ip: string;
  feed: string;
  score: number;
  country: string;
}

export interface SystemHealth {
  opensearch: 'healthy' | 'degraded' | 'down';
  redis: 'healthy' | 'degraded' | 'down';
  postgresql: 'healthy' | 'degraded' | 'down';
  pipeline: 'healthy' | 'degraded' | 'down';
}
