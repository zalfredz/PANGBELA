# ai-soc dashboard

Next.js (App Router) + TypeScript + Tailwind. Talks only to the FastAPI backend at
`NEXT_PUBLIC_API_BASE_URL` (default `http://localhost:8000`); the backend's `CORS_ORIGINS`
must include this site's origin.

Pages: `/incidents` (list, filters), `/incidents/[id]` (verdict, live agent activity over
SSE, recommendations to approve or reject, report, evidence), `/tests` (scenario results).

Requires Node.js 22 LTS.

```sh
npm ci
npm run dev      # http://localhost:3000
npm run lint
npm run build && npm start
```

Design tokens (colours with their measured contrast ratios, fonts, focus style) live in
`app/globals.css`.
