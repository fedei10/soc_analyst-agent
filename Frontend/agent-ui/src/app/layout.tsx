import { ClerkProvider } from '@clerk/nextjs'
import { shadcn } from '@clerk/ui/themes'
import type { Metadata } from 'next'
import { IBM_Plex_Mono, Inter, Space_Grotesk } from 'next/font/google'
import { NuqsAdapter } from 'nuqs/adapters/next/app'
import { Toaster } from '@/components/ui/sonner'
import './globals.css'

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-geist-sans'
})

const plexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-dm-mono'
})

const spaceGrotesk = Space_Grotesk({
  subsets: ['latin'],
  variable: '--font-display'
})

export const metadata: Metadata = {
  title: 'TSAGE SOC Console',
  description:
    'Security operations workspace for TSAGE Wazuh investigation agents.'
}

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${inter.variable} ${plexMono.variable} ${spaceGrotesk.variable}`}
    >
      <body className="antialiased">
        <ClerkProvider appearance={{ theme: shadcn }} dynamic>
          <NuqsAdapter>{children}</NuqsAdapter>
          <Toaster />
        </ClerkProvider>
      </body>
    </html>
  )
}
