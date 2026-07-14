// Popup UI: renders the stored notes and adds new ones. A bundled,
// packaged script referenced from popup.html — no remote origin.

async function render() {
  const { state } = await chrome.storage.local.get("state");
  const list = document.querySelector("#notes");
  list.replaceChildren();
  for (const note of state?.notes ?? []) {
    const li = document.createElement("li");
    li.textContent = note;
    list.append(li);
  }
}

document.querySelector("#add").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.querySelector("#text");
  const text = input.value.trim();
  if (text === "") return;
  await chrome.runtime.sendMessage({ type: "add-note", text, at: Date.now() });
  input.value = "";
  await render();
});

render();
