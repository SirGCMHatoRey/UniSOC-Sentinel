import React, { useState } from 'react'
import { NavLink } from 'react-router-dom'
import clsx from 'clsx'

interface NavItem {
  to: string
  label: string
  icon: string
}

const navItems: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', icon: '▦' },
  { to: '/logs', label: 'Logs', icon: '≡' },
  { to: '/alerts', label: 'Alerts', icon: '⚡' },
  { to: '/settings', label: 'Settings', icon: '⚙' },
]

const Sidebar: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <aside
      className={clsx(
        'flex flex-col bg-siem-surface border-r border-siem-border transition-all duration-200',
        collapsed ? 'w-14' : 'w-56'
      )}
    >
      <div className="flex items-center justify-between px-3 py-4 border-b border-siem-border">
        {!collapsed && (
          <span className="text-xs font-semibold text-gray-400 uppercase tracking-widest">
            UniSOC
          </span>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="text-gray-400 hover:text-white p-1 rounded"
          aria-label="Toggle sidebar"
        >
          {collapsed ? '→' : '←'}
        </button>
      </div>

      <nav className="flex-1 py-3 space-y-1 px-2">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-2 py-2 rounded-md text-sm transition-colors',
                isActive
                  ? 'bg-siem-accent text-white'
                  : 'text-gray-400 hover:bg-siem-border hover:text-white'
              )
            }
          >
            <span className="text-lg leading-none flex-shrink-0">{item.icon}</span>
            {!collapsed && <span>{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="p-3 border-t border-siem-border">
        <div className={clsx('flex items-center gap-2', collapsed && 'justify-center')}>
          <div className="w-2 h-2 rounded-full bg-siem-green flex-shrink-0" />
          {!collapsed && <span className="text-xs text-gray-500">System Online</span>}
        </div>
      </div>
    </aside>
  )
}

export default Sidebar
