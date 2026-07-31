import React, { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { MapContainer, TileLayer, CircleMarker, Tooltip } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import 'leaflet-defaulticon-compatibility'
import { getGeoMap } from '@/api/dashboard'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import L from 'leaflet'

// Fix leaflet default icon path issue with bundlers
delete (L.Icon.Default.prototype as unknown as Record<string, unknown>)._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
})

const GeoIPMap: React.FC = () => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'geo-map'],
    queryFn: getGeoMap,
    refetchInterval: 120_000,
  })

  if (isLoading) return <div className="flex justify-center py-8"><LoadingSpinner /></div>
  if (error) return <div className="text-siem-red text-sm">Failed to load geo data</div>

  const points = data ?? []
  const maxCount = Math.max(...points.map((p) => p.count), 1)

  return (
    <MapContainer
      center={[20, 0]}
      zoom={2}
      style={{ height: 280, width: '100%', borderRadius: 8 }}
      scrollWheelZoom={false}
    >
      <TileLayer
        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>'
        subdomains="abcd"
        maxZoom={19}
      />
      {points.map((point, i) => {
        const radius = 4 + (point.count / maxCount) * 20
        return (
          <CircleMarker
            key={i}
            center={[point.lat, point.lon]}
            radius={radius}
            pathOptions={{
              color: '#ef4444',
              fillColor: '#ef4444',
              fillOpacity: 0.6,
              weight: 1,
            }}
          >
            <Tooltip>
              <span>
                <strong>{point.country}</strong>
                <br />
                {point.count.toLocaleString()} events
              </span>
            </Tooltip>
          </CircleMarker>
        )
      })}
    </MapContainer>
  )
}

export default GeoIPMap
