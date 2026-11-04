import React, { useCallback, useEffect, useState } from 'react';
import { useI18n } from '../../i18n.jsx';
import ConfirmButton from '../../ui/ConfirmButton.jsx';
import CopyButton from '../../ui/CopyButton.jsx';
import { formatAgo, useNow } from '../../ui/sessions.js';
import { createApiToken, fetchApiTokenScopes, fetchApiTokens, fetchUsers, revokeApiToken } from '../../api.js';

const LIFETIMES = [7, 30, 90, 365];

// The signed-in person's personal API tokens: mint one for automation, see
// when each was last used, revoke. An administrator can list everyone's and
// mint tokens for service accounts, which cannot sign in to do it themselves.
export default function ApiTokensCard({ user, canSeeAll }) {
  const { t, locale } = useI18n();
  const now = useNow(60000);
  const [tokens, setTokens] = useState([]);
  const [grantable, setGrantable] = useState([]);
  const [maxDays, setMaxDays] = useState(365);
  const [showAll, setShowAll] = useState(false);
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState([]);
  const [days, setDays] = useState(30);
  const [cidrs, setCidrs] = useState('');
  const [holder, setHolder] = useState('');
  const [serviceAccounts, setServiceAccounts] = useState([]);
  const [created, setCreated] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const data = await fetchApiTokens(showAll);
      setTokens(data.items || []);
    } catch (err) {
      setError(err.message);
    }
  }, [showAll]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    fetchApiTokenScopes()
      .then((data) => {
        setGrantable(data.scopes || []);
        setMaxDays(data.maxLifetimeDays || 365);
      })
      .catch((err) => setError(err.message));
  }, []);
  useEffect(() => {
    if (!canSeeAll) return;
    fetchUsers()
      .then((data) => setServiceAccounts((data.items || []).filter((u) => u.serviceAccount)))
      .catch(() => setServiceAccounts([]));
  }, [canSeeAll]);

  const toggleScope = (scope) => {
    setScopes((current) => (current.includes(scope) ? current.filter((s) => s !== scope) : [...current, scope]));
  };

  const onCreate = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const allowedCidrs = cidrs.split(',').map((c) => c.trim()).filter(Boolean);
      const payload = { name: name.trim(), scopes, expiresInDays: days, allowedCidrs };
      if (holder) payload.serviceAccountId = Number(holder);
      const result = await createApiToken(payload);
      if (holder) setShowAll(true);
      setCreated(result);
      setName('');
      setScopes([]);
      setCidrs('');
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const onRevoke = async (id) => {
    await revokeApiToken(id);
    await load();
  };

  const statusLabel = { active: t('apiTokens.statusActive'), expired: t('apiTokens.statusExpired'), revoked: t('apiTokens.statusRevoked') };
  const lifetimes = LIFETIMES.filter((d) => d <= maxDays);

  return (
    <section className="ef-card ef-mfa">
      <div className="ef-enroll__head">
        <h2 className="ef-sectitle">{t('apiTokens.title')}</h2>
        <span className="ef-muted">{t('apiTokens.subtitle')}</span>
        <span style={{ flex: 1 }} />
        {canSeeAll && (
          <label className="ef-check"><input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />{t('apiTokens.showAll')}</label>
        )}
      </div>
      {error && <div className="ef-alert ef-alert--danger" style={{ margin: '12px 16px 0' }}>{error}</div>}
      {created && (
        <div className="ef-alert" style={{ margin: '12px 16px 0' }}>
          <strong>{t('apiTokens.createdTitle')}</strong>
          <p className="ef-hint" style={{ margin: '4px 0 8px' }}>{t('apiTokens.createdText')}</p>
          <code className="ef-mono" style={{ wordBreak: 'break-all', display: 'block', marginBottom: 8 }}>{created.token}</code>
          <span className="ef-mfa__row">
            <CopyButton text={created.token} label={t('apiTokens.copy')} />
            <button type="button" className="ef-btn ef-btn--sm" onClick={() => setCreated(null)}>{t('apiTokens.dismiss')}</button>
          </span>
        </div>
      )}

      <div className="ef-mfa__grid">
        <div className="ef-mfa__block">
          <p className="ef-hint">{t('apiTokens.intro')}</p>
          {tokens.length === 0 ? <p className="ef-muted ef-small">{t('apiTokens.none')}</p> : (
            <ul className="ef-mfa__keys">
              {tokens.map((token) => (
                <li key={token.id}>
                  <div>
                    <strong>{token.name}</strong> <span className="ef-mono ef-small">{token.tokenPrefix}…</span>{' '}
                    <span className={token.status === 'active' ? 'ef-badge ef-badge--low' : 'ef-badge'}>{statusLabel[token.status] || token.status}</span>
                    <span className="ef-muted ef-small" style={{ display: 'block' }}>
                      {(token.scopes || []).join(', ')}
                    </span>
                    <span className="ef-muted ef-small" style={{ display: 'block' }}>
                      {showAll && `${t('apiTokens.owner', { name: token.owner })} · `}
                      {t('apiTokens.expires', { when: formatAgo(token.expiresAt, now, locale) })}
                      {' · '}
                      {token.lastUsedAt
                        ? t('apiTokens.lastUsed', { when: formatAgo(token.lastUsedAt, now, locale), ip: token.lastUsedIp })
                        : t('apiTokens.neverUsed')}
                    </span>
                  </div>
                  {token.status === 'active' && (
                    <ConfirmButton
                      className="ef-btn ef-btn--sm ef-btn--danger"
                      title={t('apiTokens.revokeTitle', { name: token.name })}
                      message={t('apiTokens.revokeMsg')}
                      confirmLabel={t('apiTokens.revoke')}
                      onConfirm={() => onRevoke(token.id)}
                    >
                      {t('apiTokens.revoke')}
                    </ConfirmButton>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="ef-mfa__block">
          {grantable.length === 0 ? <p className="ef-zwarn">{t('apiTokens.noScopes')}</p> : (
            <form className="ef-zform" onSubmit={onCreate}>
              {serviceAccounts.length > 0 && (
                <>
                  <label className="ef-zform__label" htmlFor="tok-holder">{t('apiTokens.holder')}</label>
                  <select id="tok-holder" className="ef-input" style={{ width: 'auto' }} value={holder} onChange={(e) => setHolder(e.target.value)}>
                    <option value="">{t('apiTokens.holderSelf', { name: user })}</option>
                    {serviceAccounts.map((u) => <option key={u.id} value={u.id}>{u.username} · {t('users.serviceBadge')}</option>)}
                  </select>
                </>
              )}
              <label className="ef-zform__label" htmlFor="tok-name">{t('apiTokens.name')}</label>
              <input id="tok-name" className="ef-input" maxLength={64} value={name} onChange={(e) => setName(e.target.value)} placeholder={t('apiTokens.namePlaceholder')} required />
              <span className="ef-zform__label">{t('apiTokens.scopes')}</span>
              <div>
                {grantable.map((scope) => (
                  <label key={scope} className="ef-check" style={{ display: 'block' }}>
                    <input type="checkbox" checked={scopes.includes(scope)} onChange={() => toggleScope(scope)} />
                    <span className="ef-mono ef-small">{scope}</span>
                  </label>
                ))}
              </div>
              <label className="ef-zform__label" htmlFor="tok-days">{t('apiTokens.lifetime')}</label>
              <select id="tok-days" className="ef-input" style={{ width: 'auto' }} value={days} onChange={(e) => setDays(Number(e.target.value))}>
                {lifetimes.map((d) => <option key={d} value={d}>{t('apiTokens.days', { count: d })}</option>)}
              </select>
              <label className="ef-zform__label" htmlFor="tok-cidrs">{t('apiTokens.cidrs')}</label>
              <input id="tok-cidrs" className="ef-input ef-mono" value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder={t('apiTokens.cidrsPlaceholder')} />
              <span />
              <span>
                <button type="submit" className="ef-btn ef-btn--primary" disabled={busy || !name.trim() || scopes.length === 0}>
                  {busy ? t('apiTokens.creating') : t('apiTokens.create')}
                </button>
              </span>
            </form>
          )}
        </div>
      </div>
    </section>
  );
}
