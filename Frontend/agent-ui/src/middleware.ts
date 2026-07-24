import { clerkMiddleware } from '@clerk/nextjs/server'

function isPublicRoute(pathname: string) {
  return (
    pathname === '/sign-in' ||
    pathname.startsWith('/sign-in/') ||
    pathname === '/sign-up' ||
    pathname.startsWith('/sign-up/')
  )
}

export default clerkMiddleware(async (auth, request) => {
  if (isPublicRoute(request.nextUrl.pathname)) return
  if (request.nextUrl.pathname.startsWith('/api/')) {
    await auth.protect()
  } else {
    await auth.protect({
      unauthenticatedUrl: new URL('/sign-in', request.url).toString()
    })
  }
})

export const config = {
  matcher: [
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    '/(api|trpc)(.*)'
  ]
}
