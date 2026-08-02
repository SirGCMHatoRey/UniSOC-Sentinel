import React, { useState } from 'react'

interface SearchBarProps {
  onSearch: (q: string, dataset: string) => void
  initialQ?: string
  initialDataset?: string
}

const DATASETS = [
  { value: '', label: 'All Datasets' },
  { value: 'firewall', label: 'Firewall' },
  { value: 'auth', label: 'Authentication' },
  { value: 'vpn', label: 'VPN' },
  { value: 'wireless', label: 'Wireless' },
  { value: 'dhcp', label: 'DHCP' },
  { value: 'dns', label: 'DNS' },
  { value: 'syslog', label: 'Syslog' },
]

const SearchBar: React.FC<SearchBarProps> = ({ onSearch, initialQ = '', initialDataset = '' }) => {
  const [q, setQ] = useState(initialQ)
  const [dataset, setDataset] = useState(initialDataset)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSearch(q.trim(), dataset)
  }

  const handleReset = () => {
    setQ('')
    setDataset('')
    onSearch('', '')
  }

  return (
    <form onSubmit={handleSubmit} className="flex gap-2 flex-wrap">
      <input
        type="text"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Search logs... (e.g. source.ip:192.168.1.1)"
        className="flex-1 min-w-64 bg-panel border border-hairline text-ink text-sm px-3 py-2 focus:outline-none focus:ring-1 focus:ring-signal placeholder-ink-dim"
      />
      <select
        value={dataset}
        onChange={(e) => setDataset(e.target.value)}
        className="bg-panel border border-hairline text-ink text-sm px-3 py-2 focus:outline-none focus:ring-1 focus:ring-signal"
      >
        {DATASETS.map((d) => (
          <option key={d.value} value={d.value}>{d.label}</option>
        ))}
      </select>
      <button
        type="submit"
        className="px-4 py-2 bg-signal text-void text-sm font-medium hover:bg-warn transition-colors"
      >
        Search
      </button>
      <button
        type="button"
        onClick={handleReset}
        className="px-4 py-2 bg-void border border-hairline text-ink-dim text-sm hover:border-signal hover:text-ink transition-colors"
      >
        Clear
      </button>
    </form>
  )
}

export default SearchBar
