/**
 * WM SecureScan module entry.
 *
 * CSS import order is deliberate: tokens first, so nothing computes against a
 * custom property that has not been defined yet. A missing token silently
 * falls back to the initial value rather than failing, which is how a design
 * system ends up with one unstyled element that nobody notices until a
 * screenshot review.
 */

import './securescan/styles/tokens.css';
import './securescan/styles/base.css';

import { reportBootFailure, startSecureScan } from './securescan/app';

function boot(): void {
  // `.catch`, not `try`/`catch`: `startSecureScan` is async, so a throw inside
  // it -- including a missing `#ss-root`, which happens before its first
  // `await` -- becomes a rejected promise. A synchronous `try`/`catch` around a
  // floating promise never sees it, and the boot skeleton would spin forever
  // with no explanation. This is what makes `reportBootFailure` reachable.
  void startSecureScan().catch((error: unknown) => {
    console.error('[securescan] boot failed', error);
    reportBootFailure();
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot, { once: true });
} else {
  boot();
}
