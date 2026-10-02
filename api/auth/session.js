// GET /api/auth/session
//
// The browser's only window into the WorldGuard session state. The cookie is
// HttpOnly so JS can't read it directly; this endpoint verifies it server-side
// and reports the authenticated profile or `anonymous`.
//
// Full-page sign-in (Google) and logout reload the worldguard surface, but this
// endpoint also lets the frontend re-check on tab focus / pageshow so sessions
// stay in sync across tabs and after the callback redirect proves in the cookie.

export const config = { runtime: 'edge' };

import { getCorsHeaders } from '../_cors.js';
import { readSessionToken } from '../_session.js';
import { readWgSessionCookie } from '../_wg-session.js';

export default async function handler(req) {
  const corsHeaders = getCorsHeaders(req, 'GET, OPTIONS');

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method Not Allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  const presented = readWgSessionCookie(req);
  let user = null;
  if (presented) {
    const payload = await readSessionToken(presented);
    if (payload && typeof payload.u === 'string' && payload.u.length > 0) {
      user = {
        id: payload.u,
        email: typeof payload.e === 'string' ? payload.e : '',
        name: typeof payload.nm === 'string' ? payload.nm : '',
        image: typeof payload.pic === 'string' ? payload.pic : '',
        plan: 'free',
      };
    }
  }

  return new Response(JSON.stringify(user ? { status: 'authenticated', user } : { status: 'anonymous' }), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders },
  });
}