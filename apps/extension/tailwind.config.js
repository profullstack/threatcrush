/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{js,jsx,html}'],
  theme: {
    extend: {
      colors: {
        // ThreatCrush brand colors
        primary: {
          50: '#f0fff4',
          100: '#c6f6d5',
          200: '#9ae6b4',
          300: '#68d391',
          400: '#48bb78',
          500: '#00ff41',
          600: '#00e03a',
          700: '#00c233',
          800: '#00a32b',
          900: '#008522',
          950: '#006619',
        },
        // ThreatCrush dark theme
        tc: {
          bg: '#0a0a0a',
          card: '#111111',
          border: '#222222',
          text: '#e0e0e0',
          green: '#00ff41',
        },
        // Status colors
        status: {
          secure: '#00ff41',
          warning: '#f59e0b',
          threat: '#ef4444',
          info: '#6366f1',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      // Extension popup dimensions
      width: {
        popup: '380px',
      },
      height: {
        popup: '520px',
      },
      animation: {
        'spin-slow': 'spin 2s linear infinite',
        'pulse-threat': 'pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
};
