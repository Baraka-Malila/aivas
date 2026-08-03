// frontend/tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        bg:              '#0a0a0a',
        chrome:          '#0d0d0d',
        surface:         '#111111',
        modal:           '#141414',
        'surface-raised':'#161616',
        'list-row':      '#1a1a1a',
        border:          '#1e1e1e',
        'border-subtle': '#141414',
        'input-border':  '#252525',
        text:            '#e0e0e0',
        'text-secondary':'#888888',
        'text-muted':    '#555555',
        'text-faint':    '#444444',
        accent:          '#4a9eff',
        'accent-hover':  '#6cb0ff',
        'blue-tint':     '#0d1929',
        'blue-border':   '#1a2d45',
        critical:        '#ef5350',
        high:            '#ff7043',
        medium:          '#fdd835',
        low:             '#66bb6a',
      },
      fontFamily: {
        mono: ['"Fira Code"', '"SF Mono"', '"Courier New"', 'monospace'],
      },
    },
  },
  plugins: [],
}
