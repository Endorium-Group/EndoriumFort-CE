import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useI18n } from './i18n.jsx';
import Dialog from './ui/Dialog.jsx';
import ConfirmButton from './ui/ConfirmButton.jsx';
import { fetchFileshareDirectory, fetchFileshareTicket, terminateSession } from './api.js';
import {
  closeFileshareSession,
  createShare,
  deleteItem,
  downloadUrl,
  fetchDriveInfo,
  fetchShares,
  listFolder,
  makeFolder,
  openFileshareSession,
  renameItem,
  revokeShare,
  uploadFile
} from './fileshareApi.js';
import './ui/files.css';

// Drive of a "fileshare" resource, in its own tab (opened with ?files=<sessionId>).
// The bastion session decides whether the drive may be opened at all; the files
// themselves live in the separate file share service, reached under /files/
// with a cookie obtained from a bastion-signed ticket and renewed while the
// session stays active.

const joinPath = (dir, name) => (dir === '/' ? `/${name}` : `${dir}/${name}`);

function formatBytes(bytes, locale) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} ${locale === 'fr' ? 'o' : 'B'}`;
  const units = locale === 'fr' ? ['Ko', 'Mo', 'Go', 'To'] : ['KB', 'MB', 'GB', 'TB'];
  let n = value / 1024;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n.toLocaleString(locale, { maximumFractionDigits: n < 10 ? 1 : 0 })} ${units[i]}`;
}

const formatDate = (iso, locale) => {
  if (!iso) return '';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleString(locale, { dateStyle: 'short', timeStyle: 'short' });
};

const Icon = ({ d, children }) => (
  <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true">{d ? <path d={d} /> : children}</svg>
);
const FolderIcon = () => <Icon d="M3 6.5A1.5 1.5 0 0 1 4.5 5h4l2 2h9A1.5 1.5 0 0 1 21 8.5v9a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z" />;
const FileIcon = () => <Icon d="M6 3h8l4 4v14H6zM14 3v4h4" />;
const DriveIcon = () => <Icon><rect x="3" y="13" width="18" height="7" rx="1.5" /><path d="M5 13l2.5-8h9L19 13M7 16.5h.01" /></Icon>;
const SharedIcon = () => <Icon><circle cx="9" cy="8" r="3" /><path d="M3.5 19a5.5 5.5 0 0 1 11 0M16 5.5a3 3 0 0 1 0 5.5M17.5 19a5.5 5.5 0 0 0-2-4.2" /></Icon>;
const LinkIcon = () => <Icon d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" />;

export default function FileShareApp({ sessionId }) {
  const { t, locale } = useI18n();
  const [phase, setPhase] = useState('loading'); // loading | ready | ended | error
  const [fatal, setFatal] = useState('');
  const [meta, setMeta] = useState({ resourceId: 0, resourceName: '', user: '' });
  const [view, setView] = useState({ kind: 'home' }); // home | share | outgoing
  const [path, setPath] = useState('/');
  const [listing, setListing] = useState({ entries: [], writable: false, owner: '' });
  const [listError, setListError] = useState('');
  const [shares, setShares] = useState({ incoming: [], outgoing: [] });
  const [info, setInfo] = useState(null);
  const [uploads, setUploads] = useState([]);
  const [dialog, setDialog] = useState(null);
  const [notice, setNotice] = useState('');
  const [dragging, setDragging] = useState(false);
  const renewTimer = useRef(0);
  const fileInput = useRef(null);
  const rid = meta.resourceId;

  // Same theme as the main window.
  useEffect(() => {
    const dark = localStorage.getItem('endoriumfort_darkmode') === 'true';
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  }, []);

  // ── drive session: ticket from the bastion, cookie from the file service ──
  const renew = useCallback(async () => {
    window.clearTimeout(renewTimer.current);
    let ticket;
    try {
      ticket = await fetchFileshareTicket(sessionId);
    } catch (error) {
      if ([404, 409, 401, 403].includes(error.status)) setPhase('ended');
      else {
        setFatal(error.message);
        setPhase('error');
      }
      throw error;
    }
    const opened = await openFileshareSession(ticket.resourceId, ticket.ticket);
    setMeta({ resourceId: ticket.resourceId, resourceName: ticket.resourceName, user: ticket.user });
    document.title = `${ticket.resourceName} — EndoriumFort`;
    const ttl = Math.max(60, Number(opened.ttlSeconds) || 600);
    renewTimer.current = window.setTimeout(() => renew().catch(() => {}), Math.floor(ttl / 2) * 1000);
    return ticket.resourceId;
  }, [sessionId]);

  useEffect(() => {
    renew()
      .then(() => setPhase('ready'))
      .catch((error) => {
        setFatal((prev) => prev || error.message);
        setPhase((prev) => (prev === 'loading' ? 'error' : prev));
      });
    return () => window.clearTimeout(renewTimer.current);
  }, [renew]);

  // A call that finds the drive session gone renews it once, then retries.
  const call = useCallback(async (fn) => {
    try {
      return await fn();
    } catch (error) {
      if (error.status !== 401) throw error;
      await renew();
      return fn();
    }
  }, [renew]);

  const root = view.kind === 'share' ? `share:${view.share.id}` : 'home';

  const refreshShares = useCallback(() => {
    if (!rid) return Promise.resolve();
    return call(() => fetchShares(rid)).then(setShares).catch(() => {});
  }, [rid, call]);

  const refreshInfo = useCallback(() => {
    if (!rid) return;
    call(() => fetchDriveInfo(rid)).then(setInfo).catch(() => {});
  }, [rid, call]);

  const refresh = useCallback(async () => {
    if (!rid || view.kind === 'outgoing') return;
    try {
      const data = await call(() => listFolder(rid, root, path));
      setListing({ entries: data.entries || [], writable: !!data.writable, owner: data.owner || '' });
      setListError('');
    } catch (error) {
      setListing({ entries: [], writable: false, owner: '' });
      setListError(error.message);
    }
  }, [rid, root, path, view.kind, call]);

  useEffect(() => {
    if (phase !== 'ready') return;
    refresh();
  }, [phase, refresh]);

  useEffect(() => {
    if (phase !== 'ready') return;
    refreshShares();
    refreshInfo();
  }, [phase, refreshShares, refreshInfo]);

  const openView = (next) => {
    setView(next);
    setPath('/');
    setNotice('');
  };

  // ── uploads ──
  const startUploads = (files) => {
    if (!listing.writable || view.kind === 'outgoing') return;
    const dir = path;
    const uploadRoot = root;
    Array.from(files || []).forEach((file) => {
      const id = `${Date.now()}-${Math.random()}`;
      const run = (overwrite) => {
        setUploads((prev) => [...prev.filter((u) => u.id !== id), { id, name: file.name, progress: 0, status: 'running' }]);
        const job = uploadFile(rid, uploadRoot, dir, file, {
          overwrite,
          onProgress: (progress) => setUploads((prev) => prev.map((u) => (u.id === id ? { ...u, progress } : u)))
        });
        job.promise
          .then(() => {
            setUploads((prev) => prev.filter((u) => u.id !== id));
            refresh();
            refreshInfo();
          })
          .catch(async (error) => {
            if (error.status === 401) {
              try {
                await renew();
                run(overwrite);
                return;
              } catch (_) {}
            }
            if (error.status === 409 && !overwrite) {
              setUploads((prev) => prev.map((u) => (u.id === id ? { ...u, status: 'conflict', retry: () => run(true) } : u)));
              return;
            }
            setUploads((prev) => prev.map((u) => (u.id === id ? { ...u, status: 'error', error: error.message } : u)));
          });
      };
      run(false);
    });
  };

  const onDrop = (event) => {
    event.preventDefault();
    setDragging(false);
    startUploads(event.dataTransfer?.files);
  };

  const closeDrive = async () => {
    window.clearTimeout(renewTimer.current);
    if (rid) await closeFileshareSession(rid);
    await terminateSession(sessionId).catch(() => {});
    window.close();
    setPhase('ended');
  };

  const crumbs = useMemo(() => {
    const parts = path.split('/').filter(Boolean);
    return parts.map((name, i) => ({ name, path: `/${parts.slice(0, i + 1).join('/')}` }));
  }, [path]);

  if (phase === 'loading') {
    return <div className="ef ef-files ef-files--center"><p className="ef-muted">{t('files.opening')}</p></div>;
  }
  if (phase === 'ended' || phase === 'error') {
    return (
      <div className="ef ef-files ef-files--center">
        <div className="ef-card ef-files__ended">
          <h2>{phase === 'ended' ? t('files.endedTitle') : t('files.errorTitle')}</h2>
          <p className="ef-muted">{phase === 'ended' ? t('files.endedText') : fatal}</p>
          <button type="button" className="ef-btn" onClick={() => window.close()}>{t('common.close')}</button>
        </div>
      </div>
    );
  }

  const rootLabel = view.kind === 'share' ? view.share.name : t('files.myDrive');
  const quotaPct = info?.quotaBytes ? Math.min(100, Math.round((info.usedBytes / info.quotaBytes) * 100)) : 0;
  const canWrite = listing.writable && view.kind !== 'outgoing';
  const ownDrive = view.kind === 'home';

  return (
    <div className="ef ef-files">
      <header className="ef-files__hdr">
        <div className="ef-files__brand">
          <DriveIcon />
          <div>
            <strong>{meta.resourceName}</strong>
            <span className="ef-muted">{t('files.signedAs', { user: meta.user })}</span>
          </div>
        </div>
        <span className="ef-files__badge" title={t('files.isolatedHint')}>{t('files.isolated')}</span>
        <span style={{ flex: 1 }} />
        <button type="button" className="ef-btn ef-btn--sm" onClick={closeDrive}>{t('files.close')}</button>
      </header>

      <div className="ef-files__body">
        <nav className="ef-files__side" aria-label={t('files.navigation')}>
          <button type="button" className={`ef-files__nav ${ownDrive ? 'is-active' : ''}`} onClick={() => openView({ kind: 'home' })}>
            <DriveIcon />{t('files.myDrive')}
          </button>
          <button type="button" className={`ef-files__nav ${view.kind === 'outgoing' ? 'is-active' : ''}`} onClick={() => { openView({ kind: 'outgoing' }); refreshShares(); }}>
            <LinkIcon />{t('files.myShares')}
            {shares.outgoing.length > 0 && <span className="ef-count">{shares.outgoing.length}</span>}
          </button>
          <div className="ef-files__sidehead">{t('files.sharedWithMe')}</div>
          {shares.incoming.length === 0 && <p className="ef-files__sideempty ef-muted">{t('files.noIncoming')}</p>}
          {shares.incoming.map((share) => (
            <button
              key={share.id}
              type="button"
              className={`ef-files__nav ef-files__nav--share ${view.kind === 'share' && view.share.id === share.id ? 'is-active' : ''}`}
              onClick={() => openView({ kind: 'share', share })}
              title={t('files.sharedBy', { owner: share.owner })}
            >
              {share.isDir ? <FolderIcon /> : <FileIcon />}
              <span className="ef-files__navtext">
                <span>{share.name}</span>
                <small className="ef-muted">{share.owner} · {share.mode === 'rw' ? t('files.modeRw') : t('files.modeRo')}</small>
              </span>
            </button>
          ))}
          {info && (
            <div className="ef-files__quota">
              <div className="ef-files__quotabar"><span style={{ width: `${quotaPct}%` }} /></div>
              <span className="ef-muted">
                {info.quotaBytes
                  ? t('files.quota', { used: formatBytes(info.usedBytes, locale), total: formatBytes(info.quotaBytes, locale) })
                  : t('files.used', { used: formatBytes(info.usedBytes, locale) })}
              </span>
            </div>
          )}
        </nav>

        <main
          className={`ef-files__main ${dragging ? 'is-dragging' : ''}`}
          onDragOver={(event) => { if (canWrite) { event.preventDefault(); setDragging(true); } }}
          onDragLeave={(event) => { if (event.currentTarget === event.target) setDragging(false); }}
          onDrop={canWrite ? onDrop : undefined}
        >
          {view.kind === 'outgoing' ? (
            <OutgoingShares
              shares={shares.outgoing}
              locale={locale}
              onRevoke={async (share) => {
                await call(() => revokeShare(rid, share.id));
                await refreshShares();
              }}
            />
          ) : (
            <>
              <div className="ef-files__bar">
                <ol className="ef-files__crumbs">
                  <li><button type="button" onClick={() => setPath('/')}>{rootLabel}</button></li>
                  {crumbs.map((crumb) => (
                    <li key={crumb.path}><button type="button" onClick={() => setPath(crumb.path)}>{crumb.name}</button></li>
                  ))}
                </ol>
                <span style={{ flex: 1 }} />
                {view.kind === 'share' && (
                  <span className="ef-files__chip">
                    {t('files.sharedBy', { owner: view.share.owner })} · {listing.writable ? t('files.modeRw') : t('files.modeRo')}
                  </span>
                )}
                <button type="button" className="ef-btn ef-btn--sm" onClick={refresh}>{t('common.refresh')}</button>
                {canWrite && (
                  <>
                    <button type="button" className="ef-btn ef-btn--sm" onClick={() => setDialog({ type: 'mkdir' })}>{t('files.newFolder')}</button>
                    <button type="button" className="ef-btn ef-btn--sm ef-btn--primary" onClick={() => fileInput.current?.click()}>{t('files.upload')}</button>
                    <input ref={fileInput} type="file" multiple hidden onChange={(event) => { startUploads(event.target.files); event.target.value = ''; }} />
                  </>
                )}
              </div>

              {notice && <div className="ef-alert ef-alert--danger ef-files__notice">{notice}</div>}
              {listError && <div className="ef-alert ef-alert--danger ef-files__notice">{listError}</div>}

              {uploads.length > 0 && (
                <ul className="ef-files__uploads">
                  {uploads.map((u) => (
                    <li key={u.id}>
                      <span className="ef-files__upname">{u.name}</span>
                      {u.status === 'running' && <span className="ef-files__upbar"><span style={{ width: `${Math.round(u.progress * 100)}%` }} /></span>}
                      {u.status === 'conflict' && (
                        <>
                          <span className="ef-muted">{t('files.exists')}</span>
                          <button type="button" className="ef-btn ef-btn--sm" onClick={u.retry}>{t('files.replace')}</button>
                        </>
                      )}
                      {u.status === 'error' && <span className="ef-files__uperr">{u.error}</span>}
                      {u.status !== 'running' && (
                        <button type="button" className="ef-btn ef-btn--sm" onClick={() => setUploads((prev) => prev.filter((x) => x.id !== u.id))}>{t('common.close')}</button>
                      )}
                    </li>
                  ))}
                </ul>
              )}

              <div className="ef-files__tablewrap">
                <table className="ef-files__table">
                  <thead>
                    <tr>
                      <th>{t('files.name')}</th>
                      <th className="ef-files__num">{t('files.size')}</th>
                      <th>{t('files.modified')}</th>
                      <th className="ef-files__actions-h"><span className="ef-sr-only">{t('files.actions')}</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    {listing.entries.length === 0 && !listError && (
                      <tr><td colSpan={4} className="ef-files__empty ef-muted">{canWrite ? t('files.emptyWritable') : t('files.empty')}</td></tr>
                    )}
                    {listing.entries.map((entry) => {
                      const itemPath = joinPath(path, entry.name);
                      const sharedWith = ownDrive ? shares.outgoing.filter((s) => s.path === itemPath) : [];
                      return (
                        <tr key={entry.name}>
                          <td>
                            {entry.dir ? (
                              <button type="button" className="ef-files__name" onClick={() => setPath(itemPath)}>
                                <FolderIcon /><span>{entry.name}</span>
                              </button>
                            ) : (
                              <a className="ef-files__name" href={downloadUrl(rid, root, itemPath)} download>
                                <FileIcon /><span>{entry.name}</span>
                              </a>
                            )}
                            {sharedWith.length > 0 && (
                              <span className="ef-files__sharedmark" title={sharedWith.map((s) => s.grantee).join(', ')}>
                                <SharedIcon />{sharedWith.length}
                              </span>
                            )}
                          </td>
                          <td className="ef-files__num ef-muted">{entry.dir ? '—' : formatBytes(entry.size, locale)}</td>
                          <td className="ef-muted">{formatDate(entry.modified, locale)}</td>
                          <td className="ef-files__actions">
                            <a className="ef-btn ef-btn--sm" href={downloadUrl(rid, root, itemPath)} download title={entry.dir ? t('files.downloadZip') : ''}>
                              {t('files.download')}
                            </a>
                            {ownDrive && (
                              <button type="button" className="ef-btn ef-btn--sm" onClick={() => setDialog({ type: 'share', entry, path: itemPath })}>{t('files.share')}</button>
                            )}
                            {canWrite && (
                              <>
                                <button type="button" className="ef-btn ef-btn--sm" onClick={() => setDialog({ type: 'rename', entry, path: itemPath })}>{t('files.rename')}</button>
                                <ConfirmButton
                                  className="ef-btn ef-btn--sm ef-btn--danger"
                                  title={t('files.deleteTitle', { name: entry.name })}
                                  message={entry.dir ? t('files.deleteFolderMsg') : t('files.deleteFileMsg')}
                                  confirmLabel={t('common.delete')}
                                  onConfirm={async () => {
                                    await call(() => deleteItem(rid, root, itemPath));
                                    refresh();
                                    refreshInfo();
                                    refreshShares();
                                  }}
                                >
                                  {t('common.delete')}
                                </ConfirmButton>
                              </>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {canWrite && <p className="ef-files__drophint ef-muted">{t('files.dropHint')}</p>}
            </>
          )}
        </main>
      </div>

      {dialog?.type === 'mkdir' && (
        <NameDialog
          title={t('files.newFolder')}
          label={t('files.folderName')}
          confirmLabel={t('common.create')}
          onClose={() => setDialog(null)}
          onSubmit={async (name) => {
            await call(() => makeFolder(rid, root, path, name));
            refresh();
          }}
        />
      )}
      {dialog?.type === 'rename' && (
        <NameDialog
          title={t('files.renameTitle', { name: dialog.entry.name })}
          label={t('files.newName')}
          initial={dialog.entry.name}
          confirmLabel={t('files.rename')}
          onClose={() => setDialog(null)}
          onSubmit={async (name) => {
            await call(() => renameItem(rid, root, dialog.path, name));
            refresh();
            refreshShares();
          }}
        />
      )}
      {dialog?.type === 'share' && (
        <ShareDialog
          resourceId={rid}
          entry={dialog.entry}
          path={dialog.path}
          existing={shares.outgoing.filter((s) => s.path === dialog.path)}
          locale={locale}
          onClose={() => setDialog(null)}
          onShare={async (payload) => {
            await call(() => createShare(rid, payload));
            await refreshShares();
          }}
          onRevoke={async (share) => {
            await call(() => revokeShare(rid, share.id));
            await refreshShares();
          }}
        />
      )}
    </div>
  );
}

function NameDialog({ title, label, initial = '', confirmLabel, onClose, onSubmit }) {
  const { t } = useI18n();
  const [name, setName] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const submit = async (event) => {
    event.preventDefault();
    const value = name.trim();
    if (!value) return;
    setBusy(true);
    setError('');
    try {
      await onSubmit(value);
      onClose();
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };
  return (
    <Dialog title={title} onClose={onClose} width={420}>
      <form onSubmit={submit} className="ef-files__form">
        <label htmlFor="ef-files-name">{label}</label>
        <input id="ef-files-name" className="ef-input" value={name} onChange={(e) => setName(e.target.value)} autoFocus maxLength={255} />
        {error && <div className="ef-alert ef-alert--danger">{error}</div>}
        <div className="ef-files__formfoot">
          <button type="button" className="ef-btn" onClick={onClose}>{t('common.cancel')}</button>
          <button type="submit" className="ef-btn ef-btn--primary" disabled={busy || !name.trim()}>{confirmLabel}</button>
        </div>
      </form>
    </Dialog>
  );
}

const EXPIRIES = [0, 1, 7, 30, 90];

function ShareDialog({ resourceId, entry, path, existing, locale, onClose, onShare, onRevoke }) {
  const { t } = useI18n();
  const [people, setPeople] = useState([]);
  const [grantee, setGrantee] = useState('');
  const [mode, setMode] = useState('ro');
  const [days, setDays] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchFileshareDirectory(resourceId)
      .then((data) => setPeople((data.items || []).map((item) => item.username)))
      .catch((err) => setError(err.message));
  }, [resourceId]);

  const known = people.includes(grantee.trim());
  const submit = async (event) => {
    event.preventDefault();
    if (!known) {
      setError(t('files.unknownPerson'));
      return;
    }
    setBusy(true);
    setError('');
    try {
      await onShare({ path, grantee: grantee.trim(), mode: entry.dir ? mode : 'ro', expiresInDays: Number(days) || 0 });
      setGrantee('');
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  };

  return (
    <Dialog kicker={t('files.share')} title={entry.name} subtitle={t('files.shareSub')} onClose={onClose} width={520}>
      <form onSubmit={submit} className="ef-files__form">
        <label htmlFor="ef-files-grantee">{t('files.person')}</label>
        <input
          id="ef-files-grantee"
          className="ef-input"
          list="ef-files-people"
          value={grantee}
          onChange={(e) => setGrantee(e.target.value)}
          placeholder={t('files.personPlaceholder')}
          autoComplete="off"
          autoFocus
        />
        <datalist id="ef-files-people">
          {people.map((name) => <option key={name} value={name} />)}
        </datalist>
        <div className="ef-files__formrow">
          <div>
            <label htmlFor="ef-files-mode">{t('files.access')}</label>
            <select id="ef-files-mode" className="ef-input" value={entry.dir ? mode : 'ro'} onChange={(e) => setMode(e.target.value)} disabled={!entry.dir}>
              <option value="ro">{t('files.modeRo')}</option>
              <option value="rw">{t('files.modeRw')}</option>
            </select>
          </div>
          <div>
            <label htmlFor="ef-files-exp">{t('files.expires')}</label>
            <select id="ef-files-exp" className="ef-input" value={days} onChange={(e) => setDays(e.target.value)}>
              {EXPIRIES.map((d) => <option key={d} value={d}>{d === 0 ? t('files.never') : t('files.inDays', { count: d })}</option>)}
            </select>
          </div>
        </div>
        {!entry.dir && <p className="ef-hint">{t('files.fileReadOnly')}</p>}
        {error && <div className="ef-alert ef-alert--danger">{error}</div>}
        <div className="ef-files__formfoot">
          <button type="submit" className="ef-btn ef-btn--primary" disabled={busy || !grantee.trim()}>{t('files.share')}</button>
        </div>
      </form>
      {existing.length > 0 && (
        <div className="ef-files__existing">
          <h3>{t('files.sharedWith')}</h3>
          <ul>
            {existing.map((share) => (
              <li key={share.id}>
                <span><strong>{share.grantee}</strong> · {share.mode === 'rw' ? t('files.modeRw') : t('files.modeRo')}</span>
                <span className="ef-muted">{share.expiresAt ? t('files.until', { date: formatDate(share.expiresAt, locale) }) : t('files.noExpiry')}</span>
                <button type="button" className="ef-btn ef-btn--sm ef-btn--danger" onClick={() => onRevoke(share).catch((err) => setError(err.message))}>{t('files.revoke')}</button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Dialog>
  );
}

function OutgoingShares({ shares, locale, onRevoke }) {
  const { t } = useI18n();
  return (
    <>
      <div className="ef-files__bar"><h2 className="ef-files__title">{t('files.myShares')}</h2></div>
      <div className="ef-files__tablewrap">
        <table className="ef-files__table">
          <thead>
            <tr>
              <th>{t('files.item')}</th>
              <th>{t('files.person')}</th>
              <th>{t('files.access')}</th>
              <th>{t('files.expires')}</th>
              <th className="ef-files__actions-h"><span className="ef-sr-only">{t('files.actions')}</span></th>
            </tr>
          </thead>
          <tbody>
            {shares.length === 0 && <tr><td colSpan={5} className="ef-files__empty ef-muted">{t('files.noOutgoing')}</td></tr>}
            {shares.map((share) => (
              <tr key={share.id} className={share.expired ? 'is-expired' : ''}>
                <td><span className="ef-files__name is-static">{share.isDir ? <FolderIcon /> : <FileIcon />}<span className="ef-mono">{share.path}</span></span></td>
                <td>{share.grantee}</td>
                <td>{share.mode === 'rw' ? t('files.modeRw') : t('files.modeRo')}</td>
                <td className="ef-muted">{share.expired ? t('files.expired') : share.expiresAt ? formatDate(share.expiresAt, locale) : t('files.never')}</td>
                <td className="ef-files__actions">
                  <ConfirmButton
                    className="ef-btn ef-btn--sm ef-btn--danger"
                    title={t('files.revokeTitle', { person: share.grantee })}
                    message={t('files.revokeMsg')}
                    confirmLabel={t('files.revoke')}
                    onConfirm={() => onRevoke(share)}
                  >
                    {t('files.revoke')}
                  </ConfirmButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
