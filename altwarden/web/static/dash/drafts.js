// Unsaved changes for the pages that edit settings. They live here, not on a page, so moving
// between pages keeps them, and one save bar covers them all.
import { clone, toast } from "/static/dash/ui.js";

const parts = new Map();
let listener = () => {};

const dirty = (part) => JSON.stringify(part.draft) !== JSON.stringify(part.saved);

export function onChange(callback) {
  listener = callback;
}

// A page calls this each time it opens. Changes from earlier in the visit are still in the draft.
export function draftFor(key, saved, save) {
  let part = parts.get(key);
  if (part && dirty(part)) {
    part.save = save;
  } else {
    part = { key, saved, draft: clone(saved), save, redraw: null, invalid: null };
    parts.set(key, part);
  }
  return part;
}

export function touched() {
  listener();
}

export function dirtyKeys() {
  return [...parts.values()].filter(dirty).map((part) => part.key);
}

// The page behind a part closes when the visitor moves on, so its drawing code can't run any more.
export function pagesClosed() {
  for (const part of parts.values()) {
    part.redraw = null;
    part.invalid = null;
  }
}

export function forgetAll() {
  parts.clear();
  listener();
}

export function discardAll() {
  for (const part of parts.values()) {
    part.draft = clone(part.saved);
    part.redraw?.();
  }
  listener();
}

// Saves each changed part in turn. Returns the error and the part that failed, or null.
export async function saveAll() {
  for (const part of parts.values()) {
    if (!dirty(part)) continue;
    const bad = part.invalid?.();
    if (bad) {
      bad.scrollIntoView({ block: "center" });
      bad.focus();
      toast("That value is out of range.", true);
      return { part, error: null };
    }
    try {
      await part.save(part);
      part.redraw?.();
    } catch (error) {
      listener();
      toast(error.message, true);
      return { part, error };
    }
  }
  listener();
  toast("Saved.");
  return null;
}
