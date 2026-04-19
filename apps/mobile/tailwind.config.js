/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/**/*.{js,jsx,ts,tsx}',
    './src/**/*.{js,jsx,ts,tsx}',
  ],
  presets: [require('nativewind/preset')],
  theme: {
    extend: {
      colors: {
        bg: '#0a0a0a',
        primary: '#00ff41',
        card: '#111111',
        border: '#222222',
        txt: '#e0e0e0',
        dim: '#666666',
        danger: '#ff4444',
        warning: '#ffaa00',
      },
    },
  },
  plugins: [],
};
