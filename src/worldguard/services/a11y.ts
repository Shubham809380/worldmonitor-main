/**
 * Focus and scroll management for the WorldGuard authentication view.
 *
 * The auth view is a full-screen surface rather than a modal dialog, so it
 * manages the page scroll lock and a focus trap itself. Tab order is confined
 * to the view while it is mounted and restored to the trigger on exit.
 */

import { getFocusableElements } from '@/utils/dom-utils';

export interface FocusTrap {
  readonly release: () => void;
  readonly refresh: () => void;
}

function previouslyFocused(): HTMLElement | null {
  const active = document.activeElement;
  return active instanceof HTMLElement ? active : null;
}

/**
 * Confine Tab/Shift+Tab to `container` and move focus inside it on activation.
 * Returns a handle that releases the trap; releasing restores focus to whatever
 * was focused beforehand when that element is still in the document.
 */
export function trapFocus(container: HTMLElement, initialFocus?: HTMLElement): FocusTrap {
  const restoreTarget = previouslyFocused();
  let active = true;

  const onKeydown = (event: KeyboardEvent): void => {
    if (!active || event.key !== 'Tab') return;
    const focusable = getFocusableElements(container);
    if (focusable.length === 0) {
      event.preventDefault();
      container.focus();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (!first || !last) return;
    const current = document.activeElement;

    if (event.shiftKey && (current === first || !container.contains(current))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && current === last) {
      event.preventDefault();
      first.focus();
    }
  };

  container.addEventListener('keydown', onKeydown);

  const target = initialFocus ?? getFocusableElements(container)[0] ?? container;
  if (target === container && !container.hasAttribute('tabindex')) {
    container.setAttribute('tabindex', '-1');
  }
  target.focus({ preventScroll: true });

  return {
    release(): void {
      if (!active) return;
      active = false;
      container.removeEventListener('keydown', onKeydown);
      if (restoreTarget?.isConnected) restoreTarget.focus({ preventScroll: true });
    },
    refresh(): void {
      if (!active) return;
      const current = document.activeElement;
      if (current && container.contains(current)) return;
      const next = getFocusableElements(container)[0];
      next?.focus({ preventScroll: true });
    },
  };
}

/**
 * Freeze background scrolling. Sets `overflow`/`padding-right` on the document
 * element so the page behind the auth view cannot move under it.
 */
export function lockScroll(): () => void {
  const { documentElement } = document;
  const previousOverflow = documentElement.style.overflow;
  const previousPadding = documentElement.style.paddingRight;
  const scrollbarWidth = window.innerWidth - documentElement.clientWidth;

  documentElement.style.overflow = 'hidden';
  if (scrollbarWidth > 0) {
    documentElement.style.paddingRight = `${scrollbarWidth}px`;
  }

  return () => {
    documentElement.style.overflow = previousOverflow;
    documentElement.style.paddingRight = previousPadding;
  };
}

/** Focus the first element matching `selector` inside `root`, if any. */
export function focusFirst(root: ParentNode, selector: string): boolean {
  const el = root.querySelector<HTMLElement>(selector);
  if (!el) return false;
  el.focus({ preventScroll: true });
  return true;
}
