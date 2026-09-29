import React, { useEffect, useRef, useState } from 'react';
import { useI18n } from './i18n.jsx';

// Remote Browser Isolation viewer (core / CE). Streams a server-side headless
// Chromium as JPEG frames over /api/ws/rbi and forwards mouse/keyboard back as
// normalized events. The target site never reaches the operator's browser —
// only pixels do.

function buildRbiWebSocketUrl() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = new URL('/api/ws/rbi', window.location.origin);
  url.protocol = protocol;
  return url.toString();
}

// CSS -> CDP modifier bitmask (Alt=1, Ctrl=2, Meta=4, Shift=8).
function modifiersOf(e) {
  return (e.altKey ? 1 : 0) | (e.ctrlKey ? 2 : 0) | (e.metaKey ? 4 : 0) | (e.shiftKey ? 8 : 0);
}

function cdpButton(button) {
  if (button === 0) return 'left';
  if (button === 1) return 'middle';
  if (button === 2) return 'right';
  return 'none';
}

export default function RbiViewerModal({ session, onClose }) {
  const { t } = useI18n();
  const imgRef = useRef(null);
  const shellRef = useRef(null);
  const wsRef = useRef(null);
  const urlRef = useRef('');
  const clickCountRef = useRef(0);
  const [status, setStatus] = useState('connecting');
  const [statusMessage, setStatusMessage] = useState('');

  useEffect(() => {
    if (!session?.id) return undefined;
    const ws = new WebSocket(buildRbiWebSocketUrl());
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    const sizeOf = () => {
      const el = shellRef.current;
      const w = Math.max(320, Math.min(1920, Math.round(el?.clientWidth || 1280)));
      const h = Math.max(240, Math.min(1200, Math.round(el?.clientHeight || 800)));
      return { width: w, height: h };
    };

    ws.onopen = () => {
      const { width, height } = sizeOf();
      ws.send(JSON.stringify({ type: 'start', sessionId: session.id, width, height }));
    };

    ws.onmessage = (event) => {
      if (typeof event.data === 'string') {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'error') {
            setStatus('error');
            setStatusMessage(msg.message || 'error');
          } else if (msg.type === 'status') {
            if (msg.message === 'connected') {
              setStatus('connected');
              setStatusMessage('');
            } else {
              setStatusMessage(msg.message || '');
            }
          }
        } catch (_) {
          /* ignore */
        }
        return;
      }
      // Binary frame: raw JPEG bytes.
      const blob = new Blob([event.data], { type: 'image/jpeg' });
      const objectUrl = URL.createObjectURL(blob);
      if (imgRef.current) imgRef.current.src = objectUrl;
      if (urlRef.current) URL.revokeObjectURL(urlRef.current);
      urlRef.current = objectUrl;
      if (status !== 'connected') setStatus('connected');
    };

    ws.onclose = () => {
      setStatus((prev) => (prev === 'error' ? prev : 'disconnected'));
    };
    ws.onerror = () => {
      setStatus('error');
    };

    // Resize → re-issue device metrics + screencast, debounced.
    let resizeTimer = null;
    const observer = new ResizeObserver(() => {
      if (resizeTimer) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN) {
          const { width, height } = sizeOf();
          ws.send(JSON.stringify({ type: 'resize', width, height }));
        }
      }, 250);
    });
    if (shellRef.current) observer.observe(shellRef.current);

    return () => {
      observer.disconnect();
      if (resizeTimer) clearTimeout(resizeTimer);
      try { ws.close(); } catch (_) { /* noop */ }
      if (urlRef.current) {
        URL.revokeObjectURL(urlRef.current);
        urlRef.current = '';
      }
      wsRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.id]);

  const send = (obj) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
  };

  const normPoint = (e) => {
    const rect = imgRef.current?.getBoundingClientRect();
    if (!rect || rect.width === 0 || rect.height === 0) return { x: 0, y: 0 };
    return {
      x: Math.min(1, Math.max(0, (e.clientX - rect.left) / rect.width)),
      y: Math.min(1, Math.max(0, (e.clientY - rect.top) / rect.height)),
    };
  };

  const onMouseMove = (e) => {
    const { x, y } = normPoint(e);
    send({ type: 'mouse', event: 'move', x, y, button: 'none' });
  };
  const onMouseDown = (e) => {
    if (shellRef.current) shellRef.current.focus();
    clickCountRef.current = e.detail || 1;
    const { x, y } = normPoint(e);
    send({ type: 'mouse', event: 'down', x, y, button: cdpButton(e.button), clickCount: clickCountRef.current });
  };
  const onMouseUp = (e) => {
    const { x, y } = normPoint(e);
    send({ type: 'mouse', event: 'up', x, y, button: cdpButton(e.button), clickCount: clickCountRef.current });
  };
  const onWheel = (e) => {
    const { x, y } = normPoint(e);
    send({ type: 'mouse', event: 'wheel', x, y, button: 'none', deltaX: e.deltaX, deltaY: e.deltaY });
  };
  const onContextMenu = (e) => e.preventDefault();

  const onKeyDown = (e) => {
    e.preventDefault();
    const printable = e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey;
    send({
      type: 'key', event: 'down', key: e.key, code: e.code,
      keyCode: e.keyCode || 0, modifiers: modifiersOf(e),
      text: printable ? e.key : '',
    });
  };
  const onKeyUp = (e) => {
    e.preventDefault();
    send({ type: 'key', event: 'up', key: e.key, code: e.code, keyCode: e.keyCode || 0, modifiers: modifiersOf(e) });
  };

  const statusLabel =
    status === 'connected' ? t('common.connected') || 'Connected'
    : status === 'disconnected' ? t('common.disconnected') || 'Disconnected'
    : status === 'error' ? t('common.error') || 'Error'
    : t('common.connecting') || 'Connecting…';

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content vnc-modal" onClick={(e) => e.stopPropagation()}>
        <div className="vnc-modal-header">
          <div>
            <h3>Navigateur isolé (RBI)</h3>
            <p className="muted">
              {session?.protocol}://{session?.target}:{session?.port} — session #{session?.id}
            </p>
          </div>
          <div className="vnc-header-actions">
            <span className={`pill ${status === 'connected' ? 'ok' : status === 'connecting' ? 'loading' : 'offline'}`}>
              {statusLabel}
            </span>
            <button type="button" className="ghost" onClick={onClose}>
              {t('common.close') || 'Close'}
            </button>
          </div>
        </div>

        {statusMessage ? <p className="muted vnc-status-message">{statusMessage}</p> : null}

        <div
          ref={shellRef}
          className="vnc-canvas-shell rbi-canvas-shell"
          tabIndex={0}
          onMouseMove={onMouseMove}
          onMouseDown={onMouseDown}
          onMouseUp={onMouseUp}
          onWheel={onWheel}
          onContextMenu={onContextMenu}
          onKeyDown={onKeyDown}
          onKeyUp={onKeyUp}
          style={{ outline: 'none' }}
        >
          <img
            ref={imgRef}
            alt="remote browser"
            draggable={false}
            style={{ width: '100%', height: '100%', objectFit: 'contain', display: 'block', userSelect: 'none' }}
          />
        </div>
      </div>
    </div>
  );
}
