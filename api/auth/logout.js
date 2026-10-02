// POST /api/auth/logout
//
// Ends the WorldGuard session: clears the `wg-session` HttpOnly cookie and
// returns 204. Idempotent — signing out twice, or signing out while anonymous,
// is a success.
//
// This is the only sign-out entry point. It is provider-agnostic: the same
// cookie backs a password login and a Clerk-bridged one, so clearing it ends
// either. Clerk's own browser session is separate and is signed out through the
// Clerk client API (see src/worldguard/services/auth-session.ts). Cookie state is
// entirely client-side (a signed token), so there is no server-side session
// record to revoke.

import { getCorsHeaders } from '../_cors.js';
import { clearWgSessionCookies } from '../_wg-session.js';

export const config = { runtime: 'edge' };

export default async function handler(req) {
  const corsHeaders = getCorsHeaders(req, 'POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'method_not_allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders },
    });
  }

  const headers = new Headers(corsHeaders);
  headers.set('Cache-Control', 'no-store');
  for (const cookie of clearWgSessionCookies(req)) headers.append('Set-Cookie', cookie);

  return new Response(null, { status: 204, headers });
}
