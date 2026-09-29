import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import RbiViewerModal from './RbiViewerModal.jsx';
import { terminateSession } from './api.js';
import { I18nProvider } from './i18n.jsx';
import '@xterm/xterm/css/xterm.css';
import './styles.css';

const root = document.getElementById('root');

// Dedicated Remote Browser Isolation tab: opened with ?rbi=<sessionId>, it renders
// only the full-screen, decoration-free remote surface (no app chrome). Auth rides
// the session cookie (WS) + the persisted token (terminate on close). The session
// itself is created by the opener tab before this one is opened.
const rbiSessionId = new URLSearchParams(window.location.search).get('rbi');

if (rbiSessionId) {
  document.title = 'EndoriumFort — RBI';
  const closeRbiTab = () => {
    const id = Number(rbiSessionId);
    if (id) terminateSession(id).catch(() => {});
    window.close();
  };
  createRoot(root).render(
    <I18nProvider>
      <RbiViewerModal session={{ id: Number(rbiSessionId) }} fullscreen onClose={closeRbiTab} />
    </I18nProvider>
  );
} else {
  createRoot(root).render(
    <I18nProvider>
      <App />
    </I18nProvider>
  );
}
