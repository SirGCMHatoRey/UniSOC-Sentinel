import React from 'react'
import { timeRangeToParams } from '@/utils/time'

type Range = '1h' | '6h' | '24h' | '7d' | '30d'

interface TimeRangePickerProps {
  value: Range
  onChange: (range: Range, params: { from_ts: string; to_ts: string }) => void
}

const options: { label: string; value: Range }[] = [
  { label: 'Last 1h', value: '1h' },
  { label: 'Last 6h', value: '6h' },
  { label: 'Last 24h', value: '24h' },
  { label: 'Last 7d', value: '7d' },
  { label: 'Last 30d', value: '30d' },
]

const TimeRangePicker: React.FC<TimeRangePickerProps> = ({ value, onChange }) => {
  const handleChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const range = e.target.value as Range
    onChange(range, timeRangeToParams(range))
  }

  return (
    <select
      value={value}
      onChange={handleChange}
      className="bg-siem-surface border border-siem-border text-gray-200 text-sm rounded-md px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-siem-accent"
    >
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  )
}

export default TimeRangePicker
