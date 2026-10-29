// EndoriumFort — file browser on the target of an SSH session.
//
// Lists folders over SFTP, downloads through the browser's download manager and
// sends files in 4 MB chunks (the bastion stages them, enforces the size limit,
// then writes the file to the target). Targets without SFTP fall back to SCP:
// no listing, the operator types the path. What each direction allows comes
// from the resource (and the server re-checks everything).
import React, { useCallback, useEffect, useRef, useState } from 'react';
import Dialog from './Dialog.jsx';
import { useI18n } from '../i18n.jsx';
import { listSessionFiles, sessionFileDownloadUrl, uploadSessionFileChunk } from '../api.js';

const CHUNK_BYTES = 4 * 1024 * 1024;

const joinPath = (dir, name) => (dir.endsWith('/') ? `${dir}${name}` : `${dir}/${name}`);

const newUploadId = () => {
  try {
    if (window.crypto?.randomUUID) return window.crypto.randomUUID();
  } catch (_) {}
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
};

function formatSize(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

function Icon({ type }) {
  const d = type === 'dir'
    ? 'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z'
    : 'M7 3h7l5 5v13H7zM14 3v5h5';
  return (
    <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true" style={{ width: 16, height: 16, flex: 'none' }}>
      <path d={d} />
    </svg>
  );
}

export default function SshFilesDialog({ session, onClose }) {
  const { t, locale } = useI18n();
  const [listing, setListing] = useState(null);
  const [pathInput, setPathInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [progress, setProgress] = useState(null); // { name, percent }
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef(null);

  const canDownload = !!listing?.canDownload;
  const canUpload = !!listing?.canUpload;
  const maxUploadMb = Number(listing?.maxUploadMb) || 0;
  const sftp = listing ? listing.sftp !== false : true;

  const load = useCallback(async (path = '') => {
    setLoading(true);
    setError('');
    try {
      const data = await listSessionFiles(session.id, path);
      setListing(data);
      setPathInput(data.path || path);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  }, [session.id]);

  useEffect(() => { load(''); }, [load]);

  const download = (path) => {
    // An <a download> keeps the SPA in place even if the server answers an error.
    const link = document.createElement('a');
    link.href = sessionFileDownloadUrl(session.id, path);
    link.download = path.split('/').pop() || 'download';
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const sendFile = async (file, destination, overwrite = false) => {
    if (maxUploadMb && file.size > maxUploadMb * 1024 * 1024) {
      setError(t('sshTransfer.tooLarge', { name: file.name, max: maxUploadMb }));
      return false;
    }
    const uploadId = newUploadId();
    let offset = 0;
    setProgress({ name: file.name, percent: 0 });
    try {
      // An empty file is still one (empty, final) chunk.
      do {
        const chunk = file.slice(offset, offset + CHUNK_BYTES);
        const final = offset + chunk.size >= file.size;
        const result = await uploadSessionFileChunk(session.id, {
          path: destination, uploadId, offset, chunk, final, overwrite
        });
        if (result?.conflict) {
          if (result.conflict.error === 'exists') {
            setProgress(null);
            // eslint-disable-next-line no-alert
            if (!window.confirm(t('sshTransfer.exists', { name: file.name }))) return false;
            return sendFile(file, destination, true);
          }
          if (result.conflict.error === 'offset_mismatch') {
            offset = Number(result.conflict.expected) || 0;
            continue;
          }
          throw new Error(result.conflict.message || result.conflict.error);
        }
        offset += chunk.size;
        setProgress({ name: file.name, percent: file.size ? Math.round((offset / file.size) * 100) : 100 });
        if (final) {
          setNotice(t('sshTransfer.uploaded', { name: file.name, size: formatSize(result?.size ?? file.size) }));
          break;
        }
      } while (offset <= file.size);
      return true;
    } catch (err) {
      setError(err.message || String(err));
      return false;
    } finally {
      setProgress(null);
    }
  };

  const sendFiles = async (files) => {
    if (!files?.length) return;
    setError('');
    setNotice('');
    const base = sftp ? listing?.path || '.' : pathInput.trim();
    for (const file of Array.from(files)) {
      // SCP only: the typed path is the destination folder (ending in /) or file.
      const destination = sftp || base.endsWith('/') || !base ? joinPath(base || '.', file.name) : base;
      // eslint-disable-next-line no-await-in-loop
      const ok = await sendFile(file, destination);
      if (!ok) break;
    }
    if (sftp) load(listing?.path || '');
  };

  const dateOf = (epoch) => {
    if (!epoch) return '';
    return new Date(Number(epoch) * 1000).toLocaleString(locale === 'fr' ? 'fr-FR' : 'en-GB', {
      dateStyle: 'short', timeStyle: 'short'
    });
  };

  const entries = Array.isArray(listing?.entries) ? listing.entries : [];

  return (
    <Dialog
      kicker={`#${session.id}`}
      title={t('sshTransfer.title', { target: `${session.user}@${session.target}` })}
      subtitle={maxUploadMb && canUpload ? t('sshTransfer.maxUpload', { max: maxUploadMb }) : undefined}
      onClose={progress ? undefined : onClose}
      width={760}
      footer={(
        <>
          {canUpload && (
            <>
              <input ref={fileInputRef} type="file" multiple hidden onChange={(e) => { sendFiles(e.target.files); e.target.value = ''; }} />
              <button type="button" className="ef-btn ef-btn--primary" disabled={!!progress || loading} onClick={() => fileInputRef.current?.click()}>
                {t('sshTransfer.upload')}
              </button>
            </>
          )}
          <span style={{ flex: 1 }} />
          <button type="button" className="ef-btn" disabled={!!progress} onClick={onClose}>{t('sshTransfer.close')}</button>
        </>
      )}
    >
      <div
        className={dragging ? 'ef-files is-drop' : 'ef-files'}
        onDragOver={(e) => { if (canUpload && !progress) { e.preventDefault(); setDragging(true); } }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); if (canUpload && !progress) sendFiles(e.dataTransfer.files); }}
        style={dragging ? { outline: '2px dashed var(--ef-accent, #4c6ef5)', outlineOffset: 4 } : undefined}
      >
        <form
          className="ef-files__bar"
          style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}
          onSubmit={(e) => { e.preventDefault(); if (sftp) load(pathInput.trim()); }}
        >
          {sftp && (
            <button type="button" className="ef-btn ef-btn--sm" disabled={loading || !listing?.parent || listing?.path === '/'} onClick={() => load(listing.parent)} title={t('sshTransfer.up')} aria-label={t('sshTransfer.up')}>
              ↑
            </button>
          )}
          <input
            className="ef-input ef-mono"
            style={{ flex: 1 }}
            value={pathInput}
            onChange={(e) => setPathInput(e.target.value)}
            aria-label={t('sshTransfer.pathLabel')}
            spellCheck="false"
          />
          {sftp ? (
            <>
              <button type="submit" className="ef-btn ef-btn--sm" disabled={loading}>{t('sshTransfer.goTo')}</button>
              <button type="button" className="ef-btn ef-btn--sm" disabled={loading} onClick={() => load(listing?.path || '')}>{t('sshTransfer.refresh')}</button>
            </>
          ) : (
            canDownload && (
              <button type="button" className="ef-btn ef-btn--sm" disabled={!pathInput.trim()} onClick={() => download(pathInput.trim())}>
                {t('sshTransfer.downloadPath')}
              </button>
            )
          )}
        </form>

        {error && <div className="ef-alert ef-alert--danger" style={{ marginBottom: 10 }}>{error}</div>}
        {notice && <div className="ef-alert ef-alert--ok" style={{ marginBottom: 10 }}>{notice}</div>}
        {progress && (
          <div className="ef-alert" style={{ marginBottom: 10 }}>
            {t('sshTransfer.uploading', { name: progress.name, percent: progress.percent })}
            <div style={{ height: 4, background: 'var(--ef-line, #ddd)', borderRadius: 2, marginTop: 6 }}>
              <div style={{ width: `${progress.percent}%`, height: 4, background: 'var(--ef-accent, #4c6ef5)', borderRadius: 2 }} />
            </div>
          </div>
        )}
        {!canDownload && listing && <p className="ef-hint">{t('sshTransfer.noDownload')}</p>}
        {!sftp && <p className="ef-hint">{t('sshTransfer.scpOnly')}</p>}

        {sftp && (
          <div style={{ maxHeight: 420, overflow: 'auto' }}>
            <table className="ef-table">
              <thead>
                <tr>
                  <th>{t('sshTransfer.colName')}</th>
                  <th style={{ textAlign: 'right' }}>{t('sshTransfer.colSize')}</th>
                  <th>{t('sshTransfer.colDate')}</th>
                  <th aria-label={t('sshTransfer.download')} />
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => {
                  const full = joinPath(listing.path, entry.name);
                  const isDir = entry.type === 'dir';
                  return (
                    <tr key={entry.name} onDoubleClick={() => (isDir ? load(full) : canDownload && download(full))} style={{ cursor: isDir || canDownload ? 'pointer' : 'default' }}>
                      <td className="ef-mono">
                        <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                          <Icon type={isDir ? 'dir' : 'file'} />
                          {isDir ? (
                            <button type="button" className="ef-btn ef-btn--link" onClick={() => load(full)}>{entry.name}</button>
                          ) : entry.name}
                        </span>
                      </td>
                      <td className="ef-mono ef-text-2" style={{ textAlign: 'right' }}>{isDir ? '' : formatSize(entry.size)}</td>
                      <td className="ef-text-2">{dateOf(entry.mtime)}</td>
                      <td style={{ textAlign: 'right' }}>
                        {!isDir && canDownload && (
                          <button type="button" className="ef-btn ef-btn--sm" onClick={() => download(full)}>{t('sshTransfer.download')}</button>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {!loading && listing && entries.length === 0 && (
                  <tr><td colSpan={4} className="ef-muted">{t('sshTransfer.empty')}</td></tr>
                )}
              </tbody>
            </table>
            {listing?.truncated && <p className="ef-hint">{t('sshTransfer.truncated', { count: entries.length })}</p>}
          </div>
        )}
      </div>
    </Dialog>
  );
}
