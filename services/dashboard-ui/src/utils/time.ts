import { subHours, subDays, formatISO } from 'date-fns'

export function timeRangeToParams(range: '1h' | '6h' | '24h' | '7d' | '30d'): {
  from_ts: string
  to_ts: string
} {
  const now = new Date()
  let from: Date

  switch (range) {
    case '1h':
      from = subHours(now, 1)
      break
    case '6h':
      from = subHours(now, 6)
      break
    case '24h':
      from = subHours(now, 24)
      break
    case '7d':
      from = subDays(now, 7)
      break
    case '30d':
      from = subDays(now, 30)
      break
  }

  return {
    from_ts: formatISO(from),
    to_ts: formatISO(now),
  }
}
