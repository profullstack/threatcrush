/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/renderer/src/**/*.{js,ts,jsx,tsx}', './src/renderer/index.html'],
  theme: {
    extend: {
      colors: {
        bg: '#0a0a0a',
        card: '#111111',
        border: '#222222',
        primary: '#00ff41',
        dim: '#666666',
        threat: '#ff4444',
        warning: '#ffaa00',
        text: '#e0e0e0'
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace']
      }
    }
  },
  plugins: [require('tailwindcss-animate')]
}
