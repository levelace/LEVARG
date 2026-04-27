document.getElementById('capture').addEventListener('click', () => {
  const out = document.getElementById('result');
  out.textContent = 'Capturing…';
  out.className = 'meta';
  chrome.runtime.sendMessage({ type: 'capture-active-tab' }, (r) => {
    if (!r) {
      out.textContent = 'Extension service worker did not respond.';
      out.className = 'err';
      return;
    }
    if (!r.ok) {
      out.textContent = `Error: ${r.error}`;
      out.className = 'err';
      return;
    }
    out.className = 'ok';
    out.textContent = `Captured ${r.accepted} cookies (sent ${r.capturedTotal}, dropped ${r.droppedOutOfScope || 0} out-of-scope). Session: ${r.sessionId}`;
  });
});
document.getElementById('open-options').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});
