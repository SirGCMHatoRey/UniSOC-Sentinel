import React from 'react'
import ThreatOverview from './ThreatOverview'
import TopSourceIPs from './TopSourceIPs'
import FirewallActivity from './FirewallActivity'
import BlockedConnections from './BlockedConnections'
import FailedAuthAttempts from './FailedAuthAttempts'
import VPNSessions from './VPNSessions'
import WirelessActivity from './WirelessActivity'
import GeoIPMap from './GeoIPMap'
import BandwidthAnalysis from './BandwidthAnalysis'
import ThreatIntelMatches from './ThreatIntelMatches'
import SystemHealth from './SystemHealth'
import ErrorBoundary from '@/components/common/ErrorBoundary'

interface DashboardGridProps {
  fromTs: string
  toTs: string
}

interface WidgetProps {
  title: string
  children: React.ReactNode
  className?: string
}

const Widget: React.FC<WidgetProps> = ({ title, children, className = '' }) => (
  <div className={`bg-panel border border-hairline p-4 ${className}`}>
    <h3 className="text-xs font-semibold text-ink-dim uppercase tracking-widest mb-4">{title}</h3>
    <ErrorBoundary>
      {children}
    </ErrorBoundary>
  </div>
)

const DashboardGrid: React.FC<DashboardGridProps> = ({ fromTs, toTs }) => {
  return (
    <div className="space-y-4">
      {/* Stat cards row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <ThreatOverview />
      </div>

      {/* Main charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Widget title="Firewall Activity (Allow/Deny)">
          <FirewallActivity fromTs={fromTs} toTs={toTs} />
        </Widget>
        <Widget title="Bandwidth Analysis">
          <BandwidthAnalysis fromTs={fromTs} toTs={toTs} />
        </Widget>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Widget title="Blocked Connections">
          <BlockedConnections fromTs={fromTs} toTs={toTs} />
        </Widget>
        <Widget title="Failed Auth Attempts" className="lg:col-span-2">
          <FailedAuthAttempts fromTs={fromTs} toTs={toTs} />
        </Widget>
      </div>

      {/* Geo map + top IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Widget title="Geo IP Map" className="lg:col-span-2">
          <GeoIPMap />
        </Widget>
        <Widget title="Top Source IPs">
          <TopSourceIPs />
        </Widget>
      </div>

      {/* Tables row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Widget title="VPN Sessions">
          <VPNSessions />
        </Widget>
        <Widget title="Wireless Activity">
          <WirelessActivity />
        </Widget>
        <Widget title="System Health">
          <SystemHealth />
        </Widget>
      </div>

      {/* Threat intel */}
      <Widget title="Recent Threat Intel Matches">
        <ThreatIntelMatches />
      </Widget>
    </div>
  )
}

export default DashboardGrid
