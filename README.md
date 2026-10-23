# Richard & Kim — secured wedding website

This is a Cloudflare Pages **Functions + D1** project, not a single HTML file. Directly uploading only `index.html` will NOT make the RSVP/Host Portal work.

## Setup

1. Create a Cloudflare account and a D1 database named `rk-wedding`. Use the Cloudflare dashboard to execute `schema.sql` in the D1 SQL console (or `npx wrangler d1 execute rk-wedding --remote --file=./schema.sql`).
2. Create a Cloudflare Pages project connected to a **private GitHub repository** containing this project. Set **build command** to `exit 0`, **build output directory** to `public`, and **root directory** to the project root. Pages Functions in `functions/` deploy alongside `public/` when using Git integration. A dashboard direct upload of static assets alone will not deploy this backend.
3. In Pages project > Settings > Bindings, add a **D1 binding** with variable name `DB`, pointing to `rk-wedding`. Redeploy after changing bindings.
4. In Pages project > Settings > Variables and Secrets, add encrypted secrets `HOST_PASSCODE_1`, `HOST_PASSCODE_2`, and `SESSION_SECRET` (a random 32+ byte value). For your requested codes, enter `120426` and `R&K26` respectively. **Use stronger unique passphrases before going public**: these short codes have been shared in chat and are guessable. Never put these secrets in HTML, JavaScript, or Git.
5. Deploy and test the live Pages HTTPS address. Open RSVP on one device and check Host Portal on another. Save payment details in Host Portal; these become publicly readable to guests.
6. Enable Cloudflare Turnstile / WAF rate limits for public submission endpoints before inviting a large audience. Review D1 backups/exports and privacy notice/retention requirements. Test on a staging domain before sharing.

## Security boundaries

- Host passwords checked only on the server, rate-limited per IP; 8-hour HttpOnly Secure SameSite session cookie signed with `SESSION_SECRET`.
- D1 stores RSVPs and guestbook centrally. RSVP data requires an authenticated host session. Guestbook submissions await approval.
- Payment instructions are public to guests by design; **US account and routing numbers should not be displayed on a public site unless you intentionally accept this risk**. Prefer a reputable payment provider's hosted payment link instead.
- This is a starter implementation, not a security audit. Add stronger authentication (Cloudflare Access, identity provider, or MFA), CAPTCHA, spam prevention, monitoring, and a privacy policy before collecting real personal information.
- Existing localStorage RSVPs are NOT automatically migrated. Export your old responses separately if needed.
- No funds are processed, verified, or recorded by this website.

## Files

- `public/index.html`: wedding site frontend
- `functions/api/[[path]].js`: server-side endpoints
- `schema.sql`: database tables
- `README.md`: setup and security notes
