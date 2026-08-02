import { formatDistanceToNow, format } from 'date-fns'

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

export function formatDate(iso: string): string {
  try {
    return format(new Date(iso), 'yyyy-MM-dd HH:mm:ss')
  } catch {
    return iso
  }
}

export function formatRelativeTime(iso: string): string {
  try {
    return formatDistanceToNow(new Date(iso), { addSuffix: true })
  } catch {
    return iso
  }
}

export function formatSeverity(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase()
}

export function getSeverityColor(s: string): string {
  switch (s.toLowerCase()) {
    case 'critical':
    case 'high':
      return '#ff4d4d'
    case 'medium':
      return '#ffcc66'
    case 'low':
      return '#5eff8f'
    default:
      return '#7d8c7a'
  }
}
