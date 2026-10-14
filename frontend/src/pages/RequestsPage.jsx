import React, { useEffect, useMemo, useState } from 'react';
import { useI18n } from '../i18n.jsx';
import { describeAccessOutcome, describeResourcePolicy, normalizeRiskLevel } from '../accessPolicy.js';
import { formatAgo, formatClock, formatWhen, initialsOf, useNow } from '../ui/sessions.js';
import { zoneOf } from './MapPage.jsx';

// The backend expires an approved request one hour after the decision.
const APPROVAL_TTL_MS = 3600 * 1000;

const STATUS_BADGE = {
  pending: 'ef-badge ef-badge--priv',
  approved: 'ef-badge ef-badge--low',
  denied: 'ef-badge ef-badge--critical',
  expired: 'ef-badge'
};

// Effective status: an approval older than its TTL is expired even if the list was loaded earlier.
const statusOf = (request, now) => {
  const status = String(request?.status || 'pending').toLowerCase();
  if (status === 'approved') {
    const reviewed = Date.parse(request.reviewedAt || '');
    if (!Number.isNaN(reviewed) && now - reviewed > APPROVAL_TTL_MS) return 'expired';
  }
  return status;
};

export default function RequestsPage({
  requests,
  resources,
  sessions,
  currentUser,
  canReview,
  licensed,
  loading,
  error,
  onRefresh,
  onApprove,
  onDeny,
  onConnect,
  onOpenSession,
  onOpenMap,
  onUnlock
}) {
  const { t, locale } = useI18n();
  const now = useNow(30000);
  const [busy, setBusy] = useState(0);

  useEffect(() => {
    if (licensed) onRefresh();
  }, [licensed]);

  const resourceById = useMemo(() => new Map(resources.map((r) => [Number(r.id), r])), [resources]);

  const groups = useMemo(() => {
    const sorted = [...requests].sort((a, b) => Date.parse(b.createdAt || '') - Date.parse(a.createdAt || ''));
    return {
      todo: canReview ? sorted.filter((r) => statusOf(r, now) === 'pending') : [],
      mine: sorted.filter((r) => r.requester === currentUser),
      done: sorted.filter((r) => statusOf(r, now) !== 'pending' && (canReview || r.requester === currentUser))
    };
  }, [requests, canReview, currentUser, now]);

  const tabs = [
    canReview && { id: 'todo', label: t('req.toReview') },
    { id: 'mine', label: t('req.mine') },
    { id: 'done', label: t('req.history') }
  ].filter(Boolean);

  const [tab, setTab] = useState(() => (canReview ? 'todo' : 'mine'));
  const list = groups[tab] || [];
  const [selectedId, setSelectedId] = useState(null);
  const selected = list.find((r) => r.id === selectedId) || list[0] || null;

  if (!licensed) {
    return (
      <div className="ef ef-page ef-reqpage">
        <section className="ef-card ef-soon">
          <h1>{t('req.title')}</h1>
          <p>{t('req.locked')}</p>
          <button type="button" className="ef-btn" onClick={onUnlock}>{t('req.unlock')}</button>
        </section>
      </div>
    );
  }

  const decide = async (action, request) => {
    setBusy(request.id);
    try {
      await action(request.id);
    } finally {
      setBusy(0);
    }
  };

  const renderTimeline = (request, status) => {
    const items = [{ key: 'c', at: request.createdAt, text: t('req.evCreated', { user: request.requester }), tone: 'var(--ef-line-2)' }];
    if (request.reviewedAt && status !== 'pending') {
      const denied = String(request.status).toLowerCase() === 'denied';
      items.push({
        key: 'r',
        at: request.reviewedAt,
        text: t(denied ? 'req.evDenied' : 'req.evApproved', { user: request.reviewedBy || '?' }),
        tone: denied ? 'var(--ef-danger)' : 'var(--ef-ok)'
      });
    }
    sessions
      .filter((s) => String(s.grant?.approvalRef || '') === String(request.id))
      .forEach((s) => items.push({ key: `s${s.id}`, at: s.createdAt, text: t('req.evSession', { id: s.id }), tone: 'var(--ef-priv)', session: s }));
    if (status === 'expired') {
      items.push({ key: 'e', at: new Date(Date.parse(request.reviewedAt) + APPROVAL_TTL_MS).toISOString(), text: t('req.evExpired'), tone: 'var(--ef-muted)' });
    }
    items.sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
    if (status === 'pending') items.push({ key: 'w', at: null, text: t('req.evWaiting'), tone: 'var(--ef-priv)' });

    return (
      <ol className="ef-ev ef-ev--wide">
        {items.map((item) => (
          <li key={item.key}>
            <span className="ef-mono ef-muted ef-ev__t">{item.at ? formatClock(new Date(item.at), locale) : '—'}</span>
            <span className="ef-ev__rail"><span className="ef-dot" style={{ background: item.tone }} /></span>
            <span className="ef-text-2">
              {item.text}
              {item.session && item.session.status === 'active' && item.session.operator === currentUser && (
                <> · <button type="button" className="ef-btn ef-btn--link" onClick={() => onOpenSession(item.session)}>{t('map.resume')}</button></>
              )}
            </span>
          </li>
        ))}
      </ol>
    );
  };

  const renderDetail = () => {
    if (!selected) {
      return (
        <div className="ef-card ef-reqdetail ef-reqdetail--empty">
          <p>{loading ? t('common.loading') : t('req.nothingSelected')}</p>
        </div>
      );
    }
    const status = statusOf(selected, now);
    const resource = resourceById.get(Number(selected.resourceId)) || null;
    const risk = resource ? normalizeRiskLevel(resource.riskLevel) : null;
    const zone = resource ? zoneOf(resource) : '';
    // The risk already has its own badge; keep only the access rules.
    const rules = resource
      ? Array.from(new Set([...describeAccessOutcome({ ...resource, requireDualApproval: true }, t), ...describeResourcePolicy(resource, t)]))
        .filter((item) => item !== t('policy.risk', { level: risk }))
      : [];
    const own = selected.requester === currentUser;
    const approvedUntil = status === 'approved' ? new Date(Date.parse(selected.reviewedAt) + APPROVAL_TTL_MS) : null;

    return (
      <section className="ef-card ef-reqdetail" aria-label={t('req.detail')}>
        <div className="ef-reqdetail__head">
          <span className={own ? 'ef-avatar ef-avatar--lg ef-avatar--priv' : 'ef-avatar ef-avatar--lg'}>{initialsOf(selected.requester)}</span>
          <div style={{ flex: 1, minWidth: 220 }}>
            <div className="ef-reqdetail__title">
              {t('req.asks', { user: selected.requester })} <span className="ef-mono">{selected.resourceName || resource?.name || `#${selected.resourceId}`}</span>
            </div>
            <div className="ef-muted" style={{ fontSize: 12.5 }}>
              {t('req.requestNo', { id: selected.id })} · {formatWhen(selected.createdAt, locale)}
            </div>
          </div>
          <span className={STATUS_BADGE[status] || 'ef-badge'}>{t(`req.status.${status}`)}</span>
        </div>
        <div className="ef-reqdetail__body">
          {selected.justification && <blockquote className="ef-quote">« {selected.justification} »</blockquote>}
          <dl className="ef-kv ef-kv--wide">
            <dt>{t('sess.ticket')}</dt>
            <dd className="ef-mono">{selected.ticketId || '—'}</dd>
            <dt>{t('map.resource')}</dt>
            <dd>
              {resource ? (
                <>
                  <span className="ef-mono">{resource.target}:{resource.port}</span>
                  {zone && <> · {t('req.zone', { zone })}</>}
                  {' · '}<span className={`ef-badge ef-badge--${risk}`}>{t(`map.risk.${risk}`)}</span>
                </>
              ) : t('req.resourceGone')}
            </dd>
            {rules.length > 0 && (
              <>
                <dt>{t('req.rules')}</dt>
                <dd>{rules.join(' · ')}</dd>
              </>
            )}
            <dt>{t('req.requesterRole')}</dt>
            <dd>{selected.requesterRole || '—'}</dd>
            {status === 'pending' && (
              <>
                <dt>{t('req.waiting')}</dt>
                <dd>{formatAgo(selected.createdAt, now, locale)}</dd>
              </>
            )}
            {approvedUntil && (
              <>
                <dt>{t('req.validUntil')}</dt>
                <dd>{formatClock(approvedUntil, locale)}</dd>
              </>
            )}
          </dl>
          <h3 className="ef-reqdetail__sub">{t('req.timeline')}</h3>
          {renderTimeline(selected, status)}
        </div>

        {status === 'pending' && canReview && (
          <div className="ef-reqdetail__foot">
            <span className="ef-muted">{t('req.decisionHint')}</span>
            <span style={{ flex: 1 }} />
            <button type="button" className="ef-btn ef-btn--danger" disabled={busy === selected.id} onClick={() => decide(onDeny, selected)}>
              {t('req.deny')}
            </button>
            <button type="button" className="ef-btn ef-btn--primary" disabled={busy === selected.id} onClick={() => decide(onApprove, selected)}>
              {t('req.approve')}
            </button>
          </div>
        )}
        {status === 'approved' && own && resource && (
          <div className="ef-reqdetail__foot">
            <span className="ef-muted">{t('req.approvedHint', { time: formatClock(approvedUntil, locale) })}</span>
            <span style={{ flex: 1 }} />
            <button type="button" className="ef-btn ef-btn--primary" onClick={() => onConnect(resource)}>{t('map.connect')}</button>
          </div>
        )}
        {status === 'pending' && own && !canReview && (
          <div className="ef-reqdetail__foot">
            <span className="ef-muted">{t('req.pendingHint')}</span>
          </div>
        )}
      </section>
    );
  };

  return (
    <div className="ef ef-page ef-reqpage">
      <div className="ef-reqpage__head">
        <div>
          <h1>{t('req.title')}</h1>
          <p>{canReview ? t('req.subtitleReviewer') : t('req.subtitleUser')}</p>
        </div>
        <span style={{ flex: 1 }} />
        <button type="button" className="ef-btn" onClick={onRefresh} disabled={loading}>{t('common.refresh')}</button>
        <div className="ef-seg" role="tablist" aria-label={t('sess.filter')}>
          {tabs.map((item) => (
            <button
              key={item.id}
              type="button"
              role="tab"
              aria-selected={tab === item.id}
              className={tab === item.id ? 'is-on' : ''}
              onClick={() => { setTab(item.id); setSelectedId(null); }}
            >
              {item.label} <span className="ef-muted">{groups[item.id].length}</span>
            </button>
          ))}
        </div>
      </div>
      {error && <div className="ef-alert ef-alert--danger ef-reqpage__alert">{error}</div>}

      <div className="ef-reqpage__grid">
        <section className="ef-card ef-reqlist" aria-label={t('req.list')}>
          {list.map((request) => {
            const status = statusOf(request, now);
            const resource = resourceById.get(Number(request.resourceId));
            const risk = resource ? normalizeRiskLevel(resource.riskLevel) : null;
            const own = request.requester === currentUser;
            return (
              <button
                key={request.id}
                type="button"
                className={selected?.id === request.id ? 'ef-reqrow is-on' : 'ef-reqrow'}
                onClick={() => setSelectedId(request.id)}
              >
                <span className={own ? 'ef-avatar ef-avatar--priv' : 'ef-avatar'}>{initialsOf(request.requester)}</span>
                <span className="ef-reqrow__main">
                  <span className="ef-reqrow__top">
                    <span>
                      <strong>{request.requester}</strong> · <span className="ef-mono">{request.resourceName || resource?.name || `#${request.resourceId}`}</span>
                    </span>
                    <span className="ef-muted ef-reqrow__ago">{formatAgo(request.createdAt, now, locale)}</span>
                  </span>
                  <span className="ef-reqrow__reason">{request.justification || '—'}</span>
                  <span className="ef-reqrow__tags">
                    {risk && <span className={`ef-badge ef-badge--${risk}`}>{t(`map.risk.${risk}`)}</span>}
                    {request.ticketId && <span className="ef-badge ef-mono">{request.ticketId}</span>}
                    <span className={STATUS_BADGE[status] || 'ef-badge'}>{t(`req.status.${status}`)}</span>
                  </span>
                </span>
              </button>
            );
          })}
          {!list.length && (
            <div className="ef-sessempty">
              <p>{loading ? t('common.loading') : t(`req.empty.${tab}`)}</p>
              {tab === 'mine' && !loading && (
                <button type="button" className="ef-btn" onClick={onOpenMap}>{t('req.askFromMap')}</button>
              )}
            </div>
          )}
        </section>
        {renderDetail()}
      </div>
    </div>
  );
}
