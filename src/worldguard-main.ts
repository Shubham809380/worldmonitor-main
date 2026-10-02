/**
 * WorldGuard entry point.
 *
 * Loaded by `worldguard.html` as a nonce'd module. The HTML ships a static boot
 * skeleton so the page has a frame before this bundle arrives; this file swaps
 * that skeleton for the real surface and, if anything throws, hands the skeleton
 * back its failure message instead of leaving a spinner on screen forever.
 */

import './worldguard/styles/tokens.css';
import './worldguard/styles/base.css';
import './worldguard/styles/animations.css';
import './worldguard/styles/stage.css';
import './worldguard/styles/auth.css';
import './worldguard/styles/app.css';

import { reportBootFailure, startWorldGuard } from './worldguard/app';

function boot(): void {
  try {
    startWorldGuard();
  } catch (error) {
    console.error('[worldguard] boot failed', error);
    reportBootFailure();
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot, { once: true });
} else {
  boot();
}
