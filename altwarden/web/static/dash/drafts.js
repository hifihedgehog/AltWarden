// Unsaved changes for the pages that edit settings. They live here, not on a page, so moving
// between pages keeps them, and one save bar covers them all.
import { clone, toast } from "/static/dash/ui.js";

const parts = new Map();
let owner = null;  // the one server these drafts belong to
let listener = () => {};

const dirty = (part) => JSON.stringify(part.draft) !== JSON.stringify(part.saved);

export function onChange(callback) {
  listener = callback;
}

export function draftsOwner() {
  return owner;
}

// A page calls this each time it opens. Changes from earlier in the visit are still in the draft.
// A draft never crosses servers. Whatever path brought the visitor here, opening a page of another
// server drops it, because saving it there would write one server's rules into another.
// `revision` says which saved version the draft started from. A draft with changes keeps the version it
// came from, even when this visit's copy is newer, or saving would undo what someone else changed since.
export function draftFor(guildId, key, saved, save, revision) {
  if (guildId !== owner) {
    parts.clear();
    owner = guildId;
  }
  let part = parts.get(key);
  if (part && dirty(part)) {
    part.save = save;
  } else {
    part = { key, saved, draft: clone(saved), save, revision, redraw: null, invalid: null };
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
// `invalid` stays, because the boxes it reads still hold the value that mustn't be saved.
export function pagesClosed() {
  for (const part of parts.values()) part.redraw = null;
}

export function forgetAll() {
  parts.clear();
  owner = null;
  listener();
}

export function forget(key) {
  parts.delete(key);
  listener();
}

export function discardAll() {
  for (const part of parts.values()) {
    part.draft = clone(part.saved);
    part.redraw?.();
  }
  listener();
}

// Saves each changed part in turn. Returns the error and the part that failed, or null. A conflict isn't
// toasted here, because the caller offers a way out of it.
export async function saveAll() {
  for (const part of parts.values()) {
    if (!dirty(part)) continue;
    const bad = part.invalid?.();
    if (bad) {
      if (bad.isConnected) {
        bad.scrollIntoView({ block: "center" });
        bad.focus();
      }
      toast(bad.validationMessage || "That value is out of range.", true);
      return { part, error: null, invalid: true };
    }
    try {
      await part.save(part);
      part.redraw?.();
    } catch (error) {
      listener();
      if (!error.data?.conflict) toast(error.message, true);
      return { part, error };
    }
  }
  listener();
  toast("Saved.");
  return null;
}
