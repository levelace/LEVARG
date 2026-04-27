async function load() {
  const cfg = await chrome.storage.local.get(['levargIngestUrl', 'levargToken']);
  document.getElementById('ingest').value = cfg.levargIngestUrl || '';
  document.getElementById('token').value = cfg.levargToken || '';
}
async function save() {
  const ingest = document.getElementById('ingest').value.trim();
  const token = document.getElementById('token').value.trim();
  await chrome.storage.local.set({ levargIngestUrl: ingest, levargToken: token });
  document.getElementById('status').textContent = 'Saved.';
}
document.getElementById('save').addEventListener('click', save);
load();
