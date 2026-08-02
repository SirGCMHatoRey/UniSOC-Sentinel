export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    fontFamily: {
      // Workhorse: the subject is monospace-native data (IPs, timestamps,
      // rule IDs) — let the default type say so instead of dressing it in
      // a humanist sans built for prose.
      sans: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      // Display: used with restraint — wordmark and section dividers only.
      display: ['"Big Shoulders Condensed"', 'sans-serif'],
    },
    extend: {
      colors: {
        void: '#0a0c0a',
        panel: '#12160f',
        hairline: '#263026',
        signal: '#ffb454',
        ok: '#5eff8f',
        threat: '#ff4d4d',
        warn: '#ffcc66',
        ink: '#d7e0d3',
        'ink-dim': '#7d8c7a',
      },
      keyframes: {
        pulse-dot: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.35' },
        },
      },
      animation: {
        'pulse-dot': 'pulse-dot 1.6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
