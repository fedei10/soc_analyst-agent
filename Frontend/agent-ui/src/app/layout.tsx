import { ClerkProvider } from '@clerk/nextjs'
import { shadcn } from '@clerk/ui/themes'
import type { Metadata } from 'next'
import { NuqsAdapter } from 'nuqs/adapters/next/app'
import { Toaster } from '@/components/ui/sonner'
import './globals.css'

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
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased">
        <ClerkProvider appearance={{ theme: shadcn }} dynamic>
          <NuqsAdapter>{children}</NuqsAdapter>
          <Toaster />
        </ClerkProvider>
      </body>
    </html>
  )
}
