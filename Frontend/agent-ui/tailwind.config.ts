import type { Config } from 'tailwindcss'
import tailwindcssAnimate from 'tailwindcss-animate'

export default {
  darkMode: ['class'],
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}'
  ],
  theme: {
    extend: {
      colors: {
        primary: '#EDF2F3',
        primaryAccent: '#151A1D',
        brand: '#61E6A3',
        background: {
          DEFAULT: '#090B0C',
          secondary: '#151A1D'
        },
        secondary: '#EDF2F3',
        border: 'rgba(var(--color-border-default))',
        accent: '#1C2327',
        muted: '#A5B0B4',
        destructive: '#FF7777',
        positive: '#61E6A3'
      },
      fontFamily: {
        geist: 'var(--font-geist-sans)',
        dmmono: 'var(--font-dm-mono)'
      },
      borderRadius: {
        xl: '8px'
      }
    }
  },
  plugins: [tailwindcssAnimate]
} satisfies Config
