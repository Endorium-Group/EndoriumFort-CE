import React, { useEffect, useMemo, useState } from 'react';
import ConfirmButton from '../../ui/ConfirmButton.jsx';
import { useI18n } from '../../i18n.jsx';
import {
  getUserAccessProfiles,
  getUserResourcePermissions,
  grantAccessProfile,
  grantResourcePermission,
  revokeAccessProfile,
  revokeResourcePermission
} from '../../api.js';
import { formatWhen, initialsOf } from '../../ui/sessions.js';
import { zoneOf } from '../MapPage.jsx';

const ROLES = ['operator', 'admin', 'auditor'];
const EMPTY_FORM = { username: '', password: '', role: 'operator', forcePasswordRotation: true };

const mfaOf = (user, t) => {
  const parts = [];
  if (user.totpEnabled) parts.push('TOTP');
  if (user.webauthnEnabled) parts.push(t('users.keys', { count: user.webauthnCredentialCount || 1 }));
  return parts;
};

function UserForm({ initial, isNew, onSubmit, onCancel, busy, error }) {
  const { t } = useI18n();
  const [form, setForm] = useState(initial);
  useEffect(() => setForm(initial), [initial]);
  const set = (key) => (event) => setForm((prev) => ({ ...prev, [key]: event.target.type === 'checkbox' ? event.target.checked : event.target.value }));
  return (
    <form
      className="ef-uform"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(form);
      }}
    >
      {isNew && (
        <div className="ef-field">
          <label htmlFor="u-name">{t('users.username')}</label>
          <input id="u-name" className="ef-input ef-mono" value={form.username} onChange={set('username')} autoComplete="off" required />
        </div>
      )}
      <div className="ef-field">
        <label htmlFor="u-role">{t('users.role')}</label>
        <select id="u-role" className="ef-input" value={form.role} onChange={set('role')}>
          {ROLES.map((role) => <option key={role} value={role}>{t(`users.roles.${role}`)}</option>)}
        </select>
      </div>
      <div className="ef-field">
        <label htmlFor="u-pass">{isNew ? t('users.password') : t('users.newPassword')}</label>
        <input id="u-pass" className="ef-input" type="password" value={form.password} onChange={set('password')} autoComplete="new-password" required />
        {!isNew && <span className="ef-hint">{t('users.passwordRequiredHint')}</span>}
      </div>
      <label className="ef-check">
        <input type="checkbox" checked={!!form.forcePasswordRotation} onChange={set('forcePasswordRotation')} />
        {t('users.forceRotation')}
      </label>
      {form.role === 'admin' && <p className="ef-hint" style={{ margin: 0 }}>{t('users.adminMfaHint')}</p>}
      {error && <div className="ef-alert ef-alert--danger">{error}</div>}
      <div className="ef-uform__actions">
        <button type="submit" className="ef-btn ef-btn--primary" disabled={busy}>{isNew ? t('users.create') : t('common.save')}</button>
        <button type="button" className="ef-btn" onClick={onCancel}>{t('common.cancel')}</button>
      </div>
    </form>
  );
}

function AccessTab({ user, resources, accessProfiles, profilesEnabled, roleBlueprints }) {
  const { t } = useI18n();
  const [scope, setScope] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    Promise.all([
      getUserResourcePermissions(user.id),
      profilesEnabled ? getUserAccessProfiles(user.id) : Promise.resolve({ profileIds: [] })
    ])
      .then(([res, prof]) => {
        if (!active) return;
        setScope(res.resourceIds || []);
        setProfiles(prof.profileIds || []);
      })
      .catch((err) => { if (active) setError(err.message || t('users.scopeError')); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [user.id, profilesEnabled]);

  const toggleResource = async (resourceId) => {
    const has = scope.includes(resourceId);
    try {
      if (has) await revokeResourcePermission(user.id, resourceId);
      else await grantResourcePermission(user.id, resourceId);
      setScope((prev) => (has ? prev.filter((id) => id !== resourceId) : [...prev, resourceId]));
      setError('');
    } catch (err) {
      setError(err.message || t('users.scopeError'));
    }
  };

  const toggleZone = async (zone, members, allOn) => {
    for (const resource of members) {
      const has = scope.includes(resource.id);
      if (allOn === has) await toggleResource(resource.id);
    }
  };

  const toggleProfile = async (profileId) => {
    const has = profiles.includes(profileId);
    try {
      if (has) await revokeAccessProfile(user.id, profileId);
      else await grantAccessProfile(user.id, profileId);
      setProfiles((prev) => (has ? prev.filter((id) => id !== profileId) : [...prev, profileId]));
      const refreshed = await getUserResourcePermissions(user.id);
      setScope(refreshed.resourceIds || []);
    } catch (err) {
      setError(err.message || t('users.scopeError'));
    }
  };

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    const map = new Map();
    resources
      .filter((r) => !q || [r.name, r.target, r.tagsCsv].some((v) => String(v || '').toLowerCase().includes(q)))
      .forEach((resource) => {
        const zone = zoneOf(resource);
        if (!map.has(zone)) map.set(zone, []);
        map.get(zone).push(resource);
      });
    return Array.from(map.entries()).sort(([a], [b]) => (a === '' ? 1 : b === '' ? -1 : a.localeCompare(b)));
  }, [resources, query]);

  const permissions = roleBlueprints.find((role) => role.id === user.role)?.permissions || [];

  if (loading) return <p className="ef-muted" style={{ padding: '0 16px' }}>{t('common.loading')}</p>;

  return (
    <div className="ef-utab">
      {error && <div className="ef-alert ef-alert--danger">{error}</div>}
      {user.role === 'admin' ? (
        <p className="ef-hint">{t('users.adminSeesAll')}</p>
      ) : (
        <p className="ef-hint">{t('users.scopeHint', { count: scope.length })}</p>
      )}
      <label className="ef-search ef-search--sm" style={{ width: '100%' }}>
        <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" /></svg>
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('map.searchPlaceholder')} aria-label={t('map.search')} />
      </label>
      <div className="ef-scope">
        {groups.map(([zone, members]) => {
          const on = members.filter((r) => scope.includes(r.id)).length;
          const allOn = on === members.length;
          return (
            <div key={zone || 'none'} className="ef-scope__group">
              <label className="ef-check ef-scope__zone">
                <input
                  type="checkbox"
                  checked={allOn}
                  ref={(el) => { if (el) el.indeterminate = on > 0 && !allOn; }}
                  onChange={() => toggleZone(zone, members, allOn)}
                />
                <strong>{zone || t('map.noZone')}</strong>
                <span className="ef-muted">{on}/{members.length}</span>
              </label>
              {members.map((resource) => (
                <label key={resource.id} className="ef-check ef-scope__item">
                  <input type="checkbox" checked={scope.includes(resource.id)} onChange={() => toggleResource(resource.id)} />
                  <span className="ef-mono">{resource.name}</span>
                  <span className="ef-muted">{String(resource.protocol || '').toUpperCase()}</span>
                </label>
              ))}
            </div>
          );
        })}
      </div>

      {profilesEnabled && accessProfiles.length > 0 && (
        <>
          <h3 className="ef-utab__sub">{t('users.profiles')}</h3>
          {accessProfiles.map((profile) => (
            <label key={profile.id} className="ef-check ef-scope__item">
              <input type="checkbox" checked={profiles.includes(profile.id)} onChange={() => toggleProfile(profile.id)} />
              <span>{profile.name}</span>
              <span className="ef-muted ef-mono">{profile.resourceTagsCsv || profile.resourceIdsCsv || ''}</span>
            </label>
          ))}
        </>
      )}

      <h3 className="ef-utab__sub">{t('users.rolePermissions', { role: t(`users.roles.${user.role}`) })}</h3>
      <ul className="ef-permlist">
        {permissions.map((permission) => <li key={permission}>{permission}</li>)}
      </ul>
      <p className="ef-hint">{t('users.noOverrides')}</p>
    </div>
  );
}

export default function UsersAdmin({
  users,
  resources,
  auditItems,
  accessProfiles,
  profilesEnabled,
  roleBlueprints,
  currentUser,
  loading,
  onCreate,
  onUpdate,
  onDelete,
  onOpenJournal
}) {
  const { t, locale } = useI18n();
  const [query, setQuery] = useState('');
  const [role, setRole] = useState('');
  const [noMfaOnly, setNoMfaOnly] = useState(false);
  const [selectedId, setSelectedId] = useState(null);
  const [mode, setMode] = useState('view');
  const [tab, setTab] = useState('profile');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const listed = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...users]
      .filter((u) => !q || String(u.username).toLowerCase().includes(q))
      .filter((u) => !role || u.role === role)
      .filter((u) => !noMfaOnly || mfaOf(u, t).length === 0)
      .sort((a, b) => String(a.username).localeCompare(String(b.username)));
  }, [users, query, role, noMfaOnly]);

  const selected = users.find((u) => u.id === selectedId) || null;
  const admins = users.filter((u) => u.role === 'admin');
  const adminsWithoutMfa = admins.filter((u) => !mfaOf(u, t).length).length;

  const run = async (action) => {
    setBusy(true);
    setError('');
    try {
      return await action();
    } catch (err) {
      setError(err.message || t('users.saveError'));
      return null;
    } finally {
      setBusy(false);
    }
  };

  const activity = useMemo(() => (selected ? auditItems.filter((item) => item.actor === selected.username).slice(0, 12) : []), [auditItems, selected]);

  const deleteBlocked = selected && (selected.username === currentUser
    ? t('users.cannotDeleteSelf')
    : selected.role === 'admin' && admins.length <= 1 ? t('users.cannotDeleteLastAdmin') : '');

  const renderPanel = () => {
    if (mode === 'create') {
      return (
        <div className="ef-card ef-upanel">
          <div className="ef-upanel__head"><div className="ef-insp__title">{t('users.newUser')}</div></div>
          <UserForm
            initial={EMPTY_FORM}
            isNew
            busy={busy}
            error={error}
            onCancel={() => { setMode('view'); setError(''); }}
            onSubmit={async (form) => {
              const created = await run(() => onCreate({ ...form, username: form.username.trim() }));
              if (created) {
                setSelectedId(created.id);
                setMode('view');
                setTab('access');
              }
            }}
          />
        </div>
      );
    }
    if (!selected) {
      return <div className="ef-card ef-upanel ef-reqdetail--empty"><p>{t('users.selectHint')}</p></div>;
    }
    const mfa = mfaOf(selected, t);
    return (
      <div className="ef-card ef-upanel">
        <div className="ef-upanel__head">
          <span className={selected.username === currentUser ? 'ef-avatar ef-avatar--lg ef-avatar--priv' : 'ef-avatar ef-avatar--lg'}>{initialsOf(selected.username)}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="ef-insp__title ef-mono">{selected.username}</div>
            <div className="ef-muted" style={{ fontSize: 12.5 }}>{t(`users.roles.${selected.role}`)}{selected.username === currentUser ? ` · ${t('users.you')}` : ''}</div>
          </div>
        </div>
        <div style={{ padding: '0 16px 12px' }}>
          <div className="ef-seg" role="tablist" aria-label={t('users.sections')}>
            {['profile', 'access', 'activity'].map((id) => (
              <button key={id} type="button" role="tab" aria-selected={tab === id} className={tab === id ? 'is-on' : ''} onClick={() => { setTab(id); setMode('view'); }}>
                {t(`users.tab.${id}`)}
              </button>
            ))}
          </div>
        </div>

        {tab === 'profile' && mode === 'edit' && (
          <UserForm
            initial={{ username: selected.username, password: '', role: selected.role, forcePasswordRotation: !!selected.bootstrapPasswordChangeRequired }}
            busy={busy}
            error={error}
            onCancel={() => { setMode('view'); setError(''); }}
            onSubmit={async (form) => {
              const done = await run(() => onUpdate(selected.id, { password: form.password, role: form.role, forcePasswordRotation: !!form.forcePasswordRotation }));
              if (done) setMode('view');
            }}
          />
        )}
        {tab === 'profile' && mode !== 'edit' && (
          <div className="ef-utab">
            <dl className="ef-kv">
              <dt>{t('users.username')}</dt><dd className="ef-mono">{selected.username}</dd>
              <dt>{t('users.role')}</dt><dd>{t(`users.roles.${selected.role}`)}</dd>
              <dt>{t('users.mfa')}</dt>
              <dd>
                {mfa.length ? mfa.join(' + ') : <span className={selected.role === 'admin' ? 'ef-badge ef-badge--critical' : 'ef-badge'}>{t('users.noMfa')}</span>}
              </dd>
              <dt>{t('users.password')}</dt>
              <dd>{selected.bootstrapPasswordChangeRequired ? t('users.mustChange') : t('users.ok')}</dd>
              <dt>{t('users.created')}</dt><dd>{selected.createdAt ? formatWhen(selected.createdAt, locale) : '—'}</dd>
              <dt>{t('users.updated')}</dt><dd>{selected.updatedAt ? formatWhen(selected.updatedAt, locale) : '—'}</dd>
            </dl>
            {error && <div className="ef-alert ef-alert--danger" style={{ marginTop: 12 }}>{error}</div>}
          </div>
        )}
        {tab === 'access' && (
          <AccessTab user={selected} resources={resources} accessProfiles={accessProfiles} profilesEnabled={profilesEnabled} roleBlueprints={roleBlueprints} />
        )}
        {tab === 'activity' && (
          <div className="ef-utab">
            {activity.length ? (
              <ol className="ef-uact">
                {activity.map((item) => (
                  <li key={item.id}><span className="ef-mono ef-muted">{formatWhen(item.createdAt, locale)}</span><span className="ef-mono">{item.type}</span></li>
                ))}
              </ol>
            ) : <p className="ef-muted" style={{ margin: 0 }}>{t('users.noActivity')}</p>}
            <button type="button" className="ef-btn ef-btn--link" style={{ marginTop: 10, color: 'var(--ef-accent)' }} onClick={() => onOpenJournal(selected.username)}>
              {t('users.fullJournal')}
            </button>
          </div>
        )}

        {mode !== 'edit' && (
          <div className="ef-upanel__foot">
            <ConfirmButton
              title={t('confirm.deleteUser', { name: selected.username })}
              message={t('confirm.deleteUserMsg')}
              requireText={selected.username}
              confirmLabel={t('users.confirmDelete')}
              disabled={!!deleteBlocked || busy}
              onConfirm={async () => {
                const ok = await run(() => onDelete(selected.id));
                if (ok !== null) setSelectedId(null);
              }}
            >
              {t('common.delete')}
            </ConfirmButton>
            {deleteBlocked && <span className="ef-muted ef-small">{deleteBlocked}</span>}
            <span style={{ flex: 1 }} />
            {tab === 'profile' && <button type="button" className="ef-btn" onClick={() => { setMode('edit'); setError(''); }}>{t('users.edit')}</button>}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="ef ef-adminpage">
      <div className="ef-reqpage__head">
        <div>
          <h1>{t('users.title')}</h1>
          <p>
            {t('users.subtitle', { count: users.length, admins: admins.length })}
            {adminsWithoutMfa > 0 && <> · <span style={{ color: 'var(--ef-danger)' }}>{t('users.adminsWithoutMfa', { count: adminsWithoutMfa })}</span></>}
          </p>
        </div>
        <span style={{ flex: 1 }} />
        <button type="button" className="ef-btn ef-btn--primary" onClick={() => { setMode('create'); setSelectedId(null); setError(''); }}>
          <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
          {t('users.newUser')}
        </button>
      </div>

      <div className="ef-reqpage__grid">
        <div className="ef-card ef-ulist">
          <div className="ef-toolbar ef-journal__bar">
            <label className="ef-search ef-search--sm">
              <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" /></svg>
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('users.searchPlaceholder')} aria-label={t('map.search')} />
            </label>
            <select className="ef-input ef-journal__select" value={role} onChange={(event) => setRole(event.target.value)} aria-label={t('users.role')}>
              <option value="">{t('users.allRoles')}</option>
              {ROLES.map((value) => <option key={value} value={value}>{t(`users.roles.${value}`)}</option>)}
            </select>
            <label className="ef-check"><input type="checkbox" checked={noMfaOnly} onChange={(event) => setNoMfaOnly(event.target.checked)} />{t('users.noMfaOnly')}</label>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="ef-table">
              <thead>
                <tr><th>{t('users.user')}</th><th>{t('users.role')}</th><th>{t('users.mfa')}</th><th>{t('users.password')}</th><th>{t('users.created')}</th></tr>
              </thead>
              <tbody>
                {listed.map((user) => {
                  const mfa = mfaOf(user, t);
                  return (
                    <tr key={user.id} className={selected?.id === user.id ? 'is-selected' : undefined} onClick={() => { setSelectedId(user.id); setMode('view'); setError(''); }}>
                      <td>
                        <span className="ef-status">
                          <span className={user.username === currentUser ? 'ef-avatar ef-avatar--priv' : 'ef-avatar'}>{initialsOf(user.username)}</span>
                          <span className="ef-mono">{user.username}</span>
                        </span>
                      </td>
                      <td className="ef-text-2">{t(`users.roles.${user.role}`)}</td>
                      <td>
                        {mfa.length
                          ? <span className="ef-badge">{mfa.join(' + ')}</span>
                          : <span className={user.role === 'admin' ? 'ef-badge ef-badge--critical' : 'ef-badge'}>{t('users.noMfa')}</span>}
                      </td>
                      <td className="ef-text-2">{user.bootstrapPasswordChangeRequired ? t('users.mustChange') : '—'}</td>
                      <td className="ef-muted">{user.createdAt ? formatWhen(user.createdAt, locale) : '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {!listed.length && <div className="ef-sessempty"><p>{loading ? t('common.loading') : t('users.empty')}</p></div>}
          </div>
        </div>
        {renderPanel()}
      </div>
    </div>
  );
}
