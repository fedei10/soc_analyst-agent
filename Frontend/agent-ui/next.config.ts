import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  devIndicators: false,
  // Keep production builds from overwriting a live development server's files.
  distDir: process.env.NODE_ENV === 'production' ? '.next-build' : '.next'
}

export default nextConfig
