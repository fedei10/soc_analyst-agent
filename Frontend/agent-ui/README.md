# TSAGE SOC Console

Next.js 15 frontend for the TSAGE SOC orchestrator and formal investigation
workflow.

Clerk runs in Keyless mode until the development application is claimed. After
claiming it, keep the generated frontend values in `.env.local` and provide the
server credential only to FastAPI.

```bash
corepack pnpm install
corepack pnpm dev
```

Open `http://localhost:3000` and sign in. The server-side Next.js proxy obtains
the session token with `await auth()`, removes caller authorization, and
forwards the verified token to FastAPI.

The console shows `UserButton`, live tool activity, SOC specialist progress,
investigation history, reports, and human approval controls. Data is isolated
by the signed-in Clerk user.

Validation:

```bash
corepack pnpm run typecheck
corepack pnpm run build
```
