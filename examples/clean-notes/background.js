// Quick Notes background service worker. Local storage only; no network,
// no host permissions, no dynamic code. This is what a clean audit looks
// like — `crxray scan examples/clean-notes` reports zero findings.

const DEFAULT_STATE = { notes: [], updatedAt: null };

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get("state");
  if (existing.state === undefined) {
    await chrome.storage.local.set({ state: DEFAULT_STATE });
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "add-note") {
    chrome.storage.local.get("state").then(({ state }) => {
      const next = {
        notes: [...(state?.notes ?? []), message.text],
        updatedAt: message.at,
      };
      chrome.storage.local.set({ state: next }).then(() => sendResponse({ ok: true }));
    });
    return true; // async response
  }
  return false;
});
