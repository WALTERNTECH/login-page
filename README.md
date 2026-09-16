# Login page

Email + password sign-in, followed by a 6-digit code sent by email. White,
black and purple, no framework — an Express server and one static page.

## How sign-in works

1. **Password.** The server checks the email and password against a bcrypt
   hash. Unknown emails take the same time to reject as wrong passwords, so
   the response doesn't reveal which accounts exist.
2. **Code.** Only once the password matches, the server generates a random
   6-digit code, emails it, and sets a short-lived `httpOnly` cookie tying
   this browser to that code. The code is stored as an HMAC, never in plain
   text.
3. **Session.** A correct code signs the browser in with a `httpOnly`,
   `Secure`, `SameSite=Strict` session cookie valid for 12 hours.

Limits:

| What | Limit |
| --- | --- |
| Code lifetime | 5 minutes |
| Wrong codes before starting over | 5 |
| Resend cooldown | 30 seconds, at most 4 codes per sign-in |
| Failed passwords per email | 8 per 15 minutes |
| Sign-in attempts per IP | 30 per 15 minutes |
| Codes sent per email | 10 per hour |

Sessions and codes live in memory, so a restart (including Render's free
tier spinning down) signs everyone out. That's fine for a single-instance
login; move them to Redis or Postgres before running more than one instance.

## Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `LOGIN_EMAIL` | yes | The account's email address. |
| `LOGIN_PASSWORD_HASH` | yes* | bcrypt hash of the password. Generate with `npm run hash-password -- "new password"`. |
| `LOGIN_PASSWORD` | yes* | Plain-text alternative to the hash, for local use. The hash wins if both are set. |
| `RESEND_API_KEY` | for email | Sends the code. Without it, codes are written to the server log instead. |
| `OTP_FROM` | no | Sender, e.g. `Waltern Tech <login@yourdomain.com>`. Needs a verified domain. |
| `APP_NAME` | no | Name used in the email. Defaults to `Waltern Tech`. |
| `NODE_ENV` | prod | Set to `production` for `Secure` / `__Host-` cookies and HSTS. |

\* one of the two.

## Sending the code by email

Codes go through [Resend](https://resend.com) over HTTPS. SMTP isn't used
because Render's free instances block outbound SMTP ports.

1. Sign up at Resend **with the same address as `LOGIN_EMAIL`**.
2. **API Keys → Create API Key** (sending access is enough).
3. Add it as `RESEND_API_KEY` in the Render service's Environment tab.

Until you verify a domain in Resend, it sends from `onboarding@resend.dev`
and only delivers to the address that owns the Resend account — which is
why step 1 matters. After verifying a domain, set `OTP_FROM` to an address
on it.

## Running locally

```bash
npm install
LOGIN_EMAIL=you@example.com LOGIN_PASSWORD="a long password" npm run dev
```

Open <http://localhost:3000>. With no `RESEND_API_KEY`, the code appears in
the terminal.

## Changing the password

```bash
npm run hash-password -- "your new password"
```

Paste the output into `LOGIN_PASSWORD_HASH` on Render and save; the service
restarts with the new password.
