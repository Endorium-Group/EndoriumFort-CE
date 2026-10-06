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

// Keys forwarded as key events (navigation / editing / function keys). Everything
// else that produces text is captured as composed text via the hidden input's
// `input`/composition events — robust to layouts (AZERTY), AltGr, dead keys, IME.
const CONTROL_KEYS = new Set([
  'Enter', 'Tab', 'Backspace', 'Delete', 'Escape', 'Insert',
  'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight',
  'Home', 'End', 'PageUp', 'PageDown',
  'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12',
]);

export default function RbiViewerModal({ session, onClose, fullscreen = false }) {
  const { t } = useI18n();
  const canvasRef = useRef(null);
  const shellRef = useRef(null);
  const wsRef = useRef(null);
  const clickCountRef = useRef(0);
  const lastMoveRef = useRef(0);
  const uploadIdRef = useRef(1);
  const downloadsRef = useRef(new Map());
  const fileInputRef = useRef(null);
  const pendingDialogRef = useRef(0);
  const handlersRef = useRef({});
  const keyInputRef = useRef(null);   // hidden textarea capturing composed text
  const composingRef = useRef(false); // IME composition in progress
  const [status, setStatus] = useState('connecting');
  const [statusMessage, setStatusMessage] = useState('');
  const [caps, setCaps] = useState({ fileTransfer: true, clipboardPaste: true });
  const [transfer, setTransfer] = useState(null);  // {dir:'up'|'down', name, pct} | null

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
      // Binary frame. Two engines share this channel, discriminated by the first
      // byte: a full JPEG starts with 0xFF (MJPEG/CDP engine); the "tiles" engine
      // sends [u8 type][payload] where type is 1 (tile) or 2 (surface-info).
      const bytes = new Uint8Array(event.data);
      if (bytes.length === 0) return;
      if (status !== 'connected') setStatus('connected');

      // Transfer frames (not pixels): 4=file-dialog, 5/6/7=download begin/chunk/end.
      const t0 = bytes[0];
      if (t0 === 4 || t0 === 5 || t0 === 6 || t0 === 7) {
        const d = new DataView(event.data, 1);
        if (t0 === 4) {
          // [u32 seq][u8 mode][u8 multiple][u16 acceptLen][accept]
          if (d.byteLength < 8) return;
          const seq = d.getUint32(0);
          const multiple = d.getUint8(5) === 1;
          const acceptLen = d.getUint16(6);
          let accept = '';
          if (d.byteLength >= 8 + acceptLen) {
            accept = new TextDecoder().decode(new Uint8Array(event.data, 1 + 8, acceptLen));
          }
          handlersRef.current.triggerFilePicker?.(seq, accept, multiple);
          return;
        }
        if (d.byteLength < 4) return;
        const id = d.getUint32(0);
        if (t0 === 5) {
          const size = Number(d.getBigUint64(4));
          const nameLen = d.getUint16(12);
          const name = new TextDecoder().decode(new Uint8Array(event.data, 1 + 14, nameLen));
          downloadsRef.current.set(id, { name, size, chunks: [], got: 0 });
          setTransfer({ dir: 'down', name, pct: size ? 0 : null });
        } else if (t0 === 6) {
          const entry = downloadsRef.current.get(id);
          if (!entry) return;
          const chunk = new Uint8Array(event.data.slice(1 + 4));
          entry.chunks.push(chunk);
          entry.got += chunk.byteLength;
          if (entry.size) setTransfer({ dir: 'down', name: entry.name, pct: Math.round((entry.got / entry.size) * 100) });
        } else if (t0 === 7) {
          const entry = downloadsRef.current.get(id);
          downloadsRef.current.delete(id);
          if (!entry) return;
          const blob = new Blob(entry.chunks, { type: 'application/octet-stream' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = entry.name || 'download.bin';
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 10000);
          setTransfer(null);
        }
        return;
      }

      const ctx = canvasRef.current?.getContext('2d');
      if (!ctx) return;

      if (bytes[0] === 0xff) {
        // Full-frame JPEG (CDP engine): draw scaled to fill the canvas.
        createImageBitmap(new Blob([bytes], { type: 'image/jpeg' })).then((bmp) => {
          const cv = canvasRef.current;
          if (!cv) return;
          if (cv.width !== bmp.width || cv.height !== bmp.height) {
            cv.width = bmp.width; cv.height = bmp.height;
          }
          ctx.drawImage(bmp, 0, 0);
          bmp.close && bmp.close();
        }).catch(() => {});
        return;
      }

      const type = bytes[0];
      const dv = new DataView(event.data, 1);
      if (type === 2) {
        // surface-info: [u16 w][u16 h]
        if (dv.byteLength < 4) return;
        const w = dv.getUint16(0), h = dv.getUint16(1 * 2);
        const cv = canvasRef.current;
        if (cv && (cv.width !== w || cv.height !== h)) { cv.width = w; cv.height = h; }
        return;
      }
      if (type === 1) {
        // tile: [u16 x][u16 y][u16 w][u16 h][u8 format][image bytes]
        if (dv.byteLength < 9) return;
        const x = dv.getUint16(0), y = dv.getUint16(2);
        const w = dv.getUint16(4), h = dv.getUint16(6);
        const format = dv.getUint8(8);
        const imgBytes = new Uint8Array(event.data, 1 + 9);
        if (format === 2) {
          // raw RGBA
          if (imgBytes.length < w * h * 4) return;
          const data = new Uint8ClampedArray(imgBytes.buffer, imgBytes.byteOffset, w * h * 4);
          ctx.putImageData(new ImageData(data, w, h), x, y);
        } else {
          const mime = format === 1 ? 'image/webp' : 'image/jpeg';
          createImageBitmap(new Blob([imgBytes], { type: mime })).then((bmp) => {
            const c = canvasRef.current?.getContext('2d');
            if (c) c.drawImage(bmp, x, y);
            bmp.close && bmp.close();
          }).catch(() => {});
        }
      }
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
      wsRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.id]);

  // Best-effort capability probe: gate the drag-drop / paste UI to what this
  // deployment's engine supports (file transfer needs the tiles engine). The
  // backend is the real gate; defaults stay permissive if the probe fails.
  useEffect(() => {
    let token = '';
    try {
      const saved = localStorage.getItem('endoriumfort_auth');
      if (saved) token = (JSON.parse(saved) || {}).token || '';
    } catch (_) { /* ignore */ }
    let cancelled = false;
    fetch('/api/rbi/capabilities', {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      credentials: 'same-origin',
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (cancelled || !data) return;
        setCaps({
          fileTransfer: data.fileTransfer !== false,
          clipboardPaste: data.clipboardPaste !== false,
        });
      })
      .catch(() => { /* keep permissive defaults */ });
    return () => { cancelled = true; };
  }, []);

  // Grab keyboard focus once connected so typing works without a click first.
  useEffect(() => {
    if (status !== 'connected') return undefined;
    const id = setTimeout(() => { try { keyInputRef.current?.focus({ preventScroll: true }); } catch (_) { keyInputRef.current?.focus(); } }, 60);
    return () => clearTimeout(id);
  }, [status]);

  const send = (obj) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
  };

  // ── File transfer (upload hôte → cible) ──
  // Stream a File to the isolated browser as binary chunks over the same WS:
  // begin (JSON) → [u8 0x10][u32 id][bytes] chunks (with backpressure) → end.
  async function uploadFile(file, opts = {}) {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const id = (uploadIdRef.current++) >>> 0;
    send({ type: 'upload-begin', id, name: file.name, size: file.size, ...opts });
    const CHUNK = 256 * 1024;
    let off = 0;
    setTransfer({ dir: 'up', name: file.name, pct: 0 });
    try {
      while (off < file.size) {
        while (ws.bufferedAmount > 8 * 1024 * 1024) {
          // eslint-disable-next-line no-await-in-loop
          await new Promise((r) => setTimeout(r, 15));
          if (ws.readyState !== WebSocket.OPEN) return;
        }
        // eslint-disable-next-line no-await-in-loop
        const slice = await file.slice(off, off + CHUNK).arrayBuffer();
        const frame = new Uint8Array(5 + slice.byteLength);
        frame[0] = 0x10;
        new DataView(frame.buffer).setUint32(1, id);
        frame.set(new Uint8Array(slice), 5);
        ws.send(frame);
        off += slice.byteLength;
        setTransfer({ dir: 'up', name: file.name, pct: Math.round((off / Math.max(1, file.size)) * 100) });
      }
      send({ type: 'upload-end', id });
    } catch (_) {
      send({ type: 'upload-cancel', id });
    } finally {
      setTimeout(() => setTransfer(null), 1200);
    }
  }
  handlersRef.current.uploadFile = uploadFile;

  // The isolated page opened a file picker (e.g. ESXi "Upload"): open a local
  // picker and stream the chosen file back as the dialog's completion.
  function triggerFilePicker(seq, accept, multiple) {
    pendingDialogRef.current = seq;
    const input = fileInputRef.current;
    if (!input) { send({ type: 'file-pick-cancel', dialogSeq: seq }); return; }
    input.value = '';
    input.accept = accept || '';
    input.multiple = !!multiple;
    input.click();
  }
  handlersRef.current.triggerFilePicker = triggerFilePicker;

  const onFileInputChange = (e) => {
    const seq = pendingDialogRef.current;
    pendingDialogRef.current = 0;
    const files = Array.from(e.target.files || []);
    if (!files.length) { send({ type: 'file-pick-cancel', dialogSeq: seq }); return; }
    uploadFile(files[0], { dialogSeq: seq });  // v1: one file per dialog
  };
  const onFileInputCancel = () => {
    const seq = pendingDialogRef.current;
    pendingDialogRef.current = 0;
    if (seq) send({ type: 'file-pick-cancel', dialogSeq: seq });
  };

  // ── Keyboard text capture (hidden textarea) ──
  // The textarea is kept empty: we read what the browser *composed* — which
  // already accounts for layout (AZERTY), Shift, AltGr, dead keys/accents and
  // IME — forward it as `text`, then reset. Control keys go through onKeyDown.
  const focusKeyInput = () => {
    const el = keyInputRef.current;
    if (el && document.activeElement !== el) {
      try { el.focus({ preventScroll: true }); } catch (_) { el.focus(); }
    }
  };
  const flushText = () => {
    const el = keyInputRef.current;
    if (!el) return;
    const text = el.value;
    el.value = '';
    if (text) send({ type: 'text', text });
  };
  const onTextInput = () => { if (!composingRef.current) flushText(); };
  const onCompositionStart = () => { composingRef.current = true; };
  const onCompositionEnd = () => { composingRef.current = false; flushText(); };
  const onKbPaste = (e) => {
    e.preventDefault();
    if (!caps.clipboardPaste) return;
    const text = e.clipboardData?.getData('text') || '';
    if (text) send({ type: 'paste', text });
  };

  const onDragOver = (e) => {
    if (!caps.fileTransfer) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
  };
  const onDrop = (e) => {
    if (!caps.fileTransfer) return;
    e.preventDefault();
    const files = Array.from(e.dataTransfer?.files || []);
    if (!files.length) return;
    const { x, y } = normPoint(e);
    files.forEach((f) => uploadFile(f, { drop: true, x, y }));
  };

  const normPoint = (e) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect || rect.width === 0 || rect.height === 0) return { x: 0, y: 0 };
    return {
      x: Math.min(1, Math.max(0, (e.clientX - rect.left) / rect.width)),
      y: Math.min(1, Math.max(0, (e.clientY - rect.top) / rect.height)),
    };
  };

  const onMouseMove = (e) => {
    // Throttle pointer moves to ~60 Hz: raw mousemove can fire hundreds of times
    // per second, and each becomes a server-side CDP Input dispatch. Coalescing
    // cuts WS traffic + server CPU without perceptible loss.
    const now = performance.now();
    if (now - lastMoveRef.current < 16) return;
    lastMoveRef.current = now;
    const { x, y } = normPoint(e);
    send({ type: 'mouse', event: 'move', x, y, button: 'none' });
  };
  const onMouseDown = (e) => {
    focusKeyInput();
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

  // Only control/navigation/shortcut keys are forwarded as key events; printable
  // text is handled by the hidden textarea (onTextInput). AltGr (Ctrl+Alt) is NOT
  // treated as a shortcut so AZERTY symbols (@ # [ ] { } € \\ …) type normally.
  const classifyKey = (e) => {
    const altGr = typeof e.getModifierState === 'function' && e.getModifierState('AltGraph');
    const shortcut = (e.ctrlKey || e.metaKey) && !altGr;
    const pasteCombo = shortcut && caps.clipboardPaste && (e.key === 'v' || e.key === 'V');
    return { shortcut, pasteCombo, forward: CONTROL_KEYS.has(e.key) || shortcut };
  };
  const onKeyDown = (e) => {
    const { forward, pasteCombo } = classifyKey(e);
    if (pasteCombo) return;  // let the native paste event fire (onKbPaste)
    if (forward) {
      e.preventDefault();
      send({ type: 'key', event: 'down', key: e.key, code: e.code, keyCode: e.keyCode || 0, modifiers: modifiersOf(e) });
    }
    // else: text key → the textarea receives it; onTextInput forwards the text.
  };
  const onKeyUp = (e) => {
    const { forward, pasteCombo } = classifyKey(e);
    if (pasteCombo) return;
    if (forward) {
      e.preventDefault();
      send({ type: 'key', event: 'up', key: e.key, code: e.code, keyCode: e.keyCode || 0, modifiers: modifiersOf(e) });
    }
  };

  const statusLabel =
    status === 'connected' ? t('common.connected') || 'Connected'
    : status === 'disconnected' ? t('common.disconnected') || 'Disconnected'
    : status === 'error' ? t('common.error') || 'Error'
    : t('common.connecting') || 'Connecting…';

  const surface = (
    <div
      ref={shellRef}
      className="vnc-canvas-shell rbi-canvas-shell"
      tabIndex={-1}
      onMouseMove={onMouseMove}
      onMouseDown={onMouseDown}
      onMouseUp={onMouseUp}
      onWheel={onWheel}
      onContextMenu={onContextMenu}
      onDragOver={onDragOver}
      onDrop={onDrop}
      style={fullscreen
        ? { outline: 'none', width: '100%', height: '100%', flex: 1, position: 'relative' }
        : { outline: 'none', position: 'relative' }}
    >
      <canvas
        ref={canvasRef}
        style={{ width: '100%', height: '100%', objectFit: 'contain', display: 'block', userSelect: 'none' }}
      />
      {/* Hidden, always-empty capture field: owns keyboard focus so the browser
          composes text (layout/AltGr/dead keys/IME) for us. pointer-events:none
          lets clicks reach the canvas; we focus it programmatically on mousedown. */}
      <textarea
        ref={keyInputRef}
        onKeyDown={onKeyDown}
        onKeyUp={onKeyUp}
        onInput={onTextInput}
        onCompositionStart={onCompositionStart}
        onCompositionEnd={onCompositionEnd}
        onPaste={onKbPaste}
        autoCapitalize="none"
        autoCorrect="off"
        autoComplete="off"
        spellCheck={false}
        aria-hidden="true"
        tabIndex={-1}
        style={{
          position: 'absolute', inset: 0, width: '100%', height: '100%',
          opacity: 0, border: 'none', resize: 'none', padding: 0, margin: 0,
          pointerEvents: 'none', caretColor: 'transparent', color: 'transparent',
          background: 'transparent', overflow: 'hidden', whiteSpace: 'pre',
        }}
      />
    </div>
  );

  // Decoration-free transfer affordances: a hidden picker (driven by the isolated
  // page's file dialog) + a transient progress toast for up/downloads.
  const transferUi = (
    <>
      <input
        ref={fileInputRef}
        type="file"
        style={{ display: 'none' }}
        onChange={onFileInputChange}
        onCancel={onFileInputCancel}
      />
      {transfer && (
        <div style={{
          position: 'fixed', bottom: '16px', left: '50%', transform: 'translateX(-50%)',
          background: 'rgba(20,22,28,0.92)', color: '#fff', padding: '8px 14px',
          borderRadius: '8px', fontFamily: 'system-ui, sans-serif', fontSize: '13px',
          pointerEvents: 'none', zIndex: 10, maxWidth: '80vw', whiteSpace: 'nowrap',
          overflow: 'hidden', textOverflow: 'ellipsis',
        }}>
          {transfer.dir === 'up' ? '↑' : '↓'} {transfer.name}
          {typeof transfer.pct === 'number' ? ` — ${transfer.pct}%` : '…'}
        </div>
      )}
    </>
  );

  // Fullscreen: a decoration-free page (own tab) — just the remote surface, with
  // a transient status overlay while connecting and a minimal floating close.
  if (fullscreen) {
    return (
      <div
        style={{
          position: 'fixed', inset: 0, width: '100vw', height: '100vh',
          background: '#000', display: 'flex', flexDirection: 'column', overflow: 'hidden'
        }}
      >
        {surface}
        {transferUi}
        {status !== 'connected' && (
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
            color: '#fff', fontFamily: 'system-ui, sans-serif', textAlign: 'center', pointerEvents: 'none'
          }}>
            <div style={{ fontSize: '15px', opacity: 0.85 }}>{statusLabel}</div>
            {statusMessage ? <div style={{ fontSize: '13px', opacity: 0.6, marginTop: '6px' }}>{statusMessage}</div> : null}
          </div>
        )}
      </div>
    );
  }

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

        {surface}
        {transferUi}
      </div>
    </div>
  );
}
