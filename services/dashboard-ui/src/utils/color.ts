export function severityToClass(s: string): string {
  switch (s.toLowerCase()) {
    case 'critical':
      return 'bg-siem-red text-white'
    case 'high':
      return 'bg-siem-orange text-white'
    case 'medium':
      return 'bg-siem-yellow text-black'
    case 'low':
      return 'bg-siem-blue text-white'
    case 'info':
      return 'bg-siem-green text-black'
    default:
      return 'bg-gray-600 text-white'
  }
}

export function severityToBorderClass(s: string): string {
  switch (s.toLowerCase()) {
    case 'critical':
      return 'border-siem-red'
    case 'high':
      return 'border-siem-orange'
    case 'medium':
      return 'border-siem-yellow'
    case 'low':
      return 'border-siem-blue'
    case 'info':
      return 'border-siem-green'
    default:
      return 'border-gray-600'
  }
}
