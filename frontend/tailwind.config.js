// frontend/tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0a0a0a',
        surface: '#111111',
        'surface-raised': '#161616',
        border: '#1e1e1e',
        'border-subtle': '#141414',
        text: '#e0e0e0',
        'text-muted': '#666666',
        accent: '#4a9eff',
        critical: '#ef5350',
        high: '#ff7043',
        medium: '#fdd835',
        low: '#66bb6a',
      },
      fontFamily: {
        mono: ['"Fira Code"', '"SF Mono"', '"Courier New"', 'monospace'],
      },
    },
  },
  plugins: [],
}
