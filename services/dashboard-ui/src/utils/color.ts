// Severity is shown as an ascending signal-strength meter (1-5 bars), not a
// pill badge — see SeverityBadge. These map the five canonical severity
// tiers to bar count and color.

const LEVELS: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
}

export function severityToLevel(s: string): number {
  return LEVELS[s.toLowerCase()] ?? 1
}

export function severityToBarColor(s: string): string {
  switch (s.toLowerCase()) {
    case 'critical':
    case 'high':
      return 'bg-threat'
    case 'medium':
      return 'bg-warn'
    case 'low':
      return 'bg-ok'
    default:
      return 'bg-ink-dim'
  }
}

export function severityToTextClass(s: string): string {
  switch (s.toLowerCase()) {
    case 'critical':
    case 'high':
      return 'text-threat'
    case 'medium':
      return 'text-warn'
    case 'low':
      return 'text-ok'
    default:
      return 'text-ink-dim'
  }
}
