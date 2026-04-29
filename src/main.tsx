import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

// Patch fetch to handle pages served behind Basic Auth (e.g. tunnel URLs).
// Browsers resolve relative paths using the page origin which may embed
// credentials; the Fetch API rejects credential-bearing URLs.
const _fetch = window.fetch.bind(window);
window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
  if (typeof input === 'string' && input.startsWith('/')) {
    input = new URL(input, window.location.origin).href;
  }
  return _fetch(input, init);
};

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
