/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#080b12',
        panel: '#10151f',
        line: '#202a38',
        cyan: '#55d6e8',
        lime: '#b6e36b',
        amber: '#f4bd72',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular'],
      },
      boxShadow: {
        glow: '0 0 32px rgba(85, 214, 232, 0.08)',
      },
    },
  },
  plugins: [],
}
