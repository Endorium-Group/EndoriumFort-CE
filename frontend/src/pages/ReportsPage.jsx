import React, { useEffect, useMemo, useState } from 'react';
import { useI18n } from '../i18n.jsx';
import { fetchReport, fetchReportCsv } from '../api.js';

const PERIODS = ['day', 'month', 'quarter', 'year'];

// Which <input> the period picker shows, and the value it carries.
const pickerOf = (period, anchor) => {
  if (period === 'day') return { type: 'date', value: anchor };
  if (period === 'month' || period === 'quarter') return { type: 'month', value: anchor.slice(0, 7) };
  return { type: 'number', value: anchor.slice(0, 4) };
};

// A picked value back to the YYYY-MM-DD anchor the server expects.
const anchorOf = (period, raw) => {
  if (period === 'day') return /^\d{4}-\d{2}-\d{2}$/.test(raw) ? raw : '';
  if (period === 'month' || period === 'quarter') return /^\d{4}-\d{2}$/.test(raw) ? `${raw}-01` : '';
  return /^\d{4}$/.test(raw) ? `${raw}-01-01` : '';
};

const todayAnchor = () => new Date().toISOString().slice(0, 10);

// The step from one period to the previous or the next one, so the arrows can
// walk the calendar without a round trip.
const shiftAnchor = (period, anchor, step) => {
  const [y, m, d] = anchor.split('-').map(Number);
  if (period === 'day') {
    const date = new Date(Date.UTC(y, m - 1, d + step));
    return date.toISOString().slice(0, 10);
  }
  const months = period === 'month' ? 1 : period === 'quarter' ? 3 : 12;
  const date = new Date(Date.UTC(y, m - 1 + months * step, 1));
  return date.toISOString().slice(0, 10);
};

const pct = (value, total) => (total > 0 ? Math.round((value / total) * 100) : 0);

function Trend({ value, previous, t }) {
  if (!previous && !value) return null;
  if (!previous) return <span className="ef-trend ef-trend--new">{t('reports.trendNew')}</span>;
  const change = Math.round(((value - previous) / previous) * 100);
  if (change === 0) return <span className="ef-trend">{t('reports.trendFlat')}</span>;
  const up = change > 0;
  return (
    <span className={up ? 'ef-trend ef-trend--up' : 'ef-trend ef-trend--down'}>
      {up ? '▲' : '▼'} {Math.abs(change)}%
    </span>
  );
}

// One figure of the period, with how it compares to the period before.
function Kpi({ label, value, previous, tone, t }) {
  return (
    <div className="ef-kpi">
      <span className="ef-kpi__label">{label}</span>
      <b className={tone ? `ef-kpi__value ef-kpi__value--${tone}` : 'ef-kpi__value'}>{value}</b>
      <Trend value={value} previous={previous} t={t} />
    </div>
  );
}

// Events per bucket (hours of a day, days of a month or a quarter, months of a
// year). A table, so the figures stay readable to a screen reader.
function Timeline({ buckets, unit, locale, t }) {
  const peak = Math.max(1, ...buckets.map((b) => b.events));
  const label = (value) => {
    if (unit !== 'day') return value;
    const date = new Date(`${value}T00:00:00Z`);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleDateString(locale === 'fr' ? 'fr-FR' : 'en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' });
  };
  return (
    <div className="ef-timeline" role="img" aria-label={t('reports.timelineAlt', { count: buckets.length, peak })}>
      {buckets.map((bucket) => (
        <div key={bucket.label} className="ef-timeline__col" title={t('reports.bucketTitle', {
          label: label(bucket.label),
          events: bucket.events,
          sessions: bucket.sessions,
          failures: bucket.failures
        })}>
          <span className="ef-timeline__bars">
            {bucket.events > 0 && (
              <span className="ef-timeline__bar" style={{ height: `${(bucket.events / peak) * 100}%` }} />
            )}
            {bucket.failures > 0 && (
              <span className="ef-timeline__bar ef-timeline__bar--fail" style={{ height: `${(bucket.failures / peak) * 100}%` }} />
            )}
          </span>
        </div>
      ))}
    </div>
  );
}

// A "top N" list as a share of the busiest entry.
function TopList({ title, items, empty }) {
  const peak = items.length ? Math.max(1, items[0].count) : 1;
  return (
    <div className="ef-card ef-toplist">
      <h2>{title}</h2>
      {items.length === 0 && <p className="ef-muted">{empty}</p>}
      <ol>
        {items.map((item) => (
          <li key={item.name}>
            <span className="ef-toplist__name" title={item.name}>{item.name}</span>
            <span className="ef-toplist__meter" aria-hidden="true">
              <span style={{ width: `${(item.count / peak) * 100}%` }} />
            </span>
            <span className="ef-toplist__count ef-mono">{item.count}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

// Daily, monthly, quarterly and annual reports. Everything is aggregated on the
// server from the audit log (archives included), so the figures cover the whole
// retention window and not only what is in memory since the last restart.
export default function ReportsPage() {
  const { t, locale } = useI18n();
  const [period, setPeriod] = useState('day');
  const [anchor, setAnchor] = useState(todayAnchor);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [exporting, setExporting] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    let live = true;
    setLoading(true);
    setError('');
    fetchReport({ period, date: anchor, top: 10 })
      .then((data) => { if (live) { setReport(data); setLoading(false); } })
      .catch((err) => { if (live) { setError(err.message || t('reports.loadError')); setLoading(false); } });
    return () => { live = false; };
  }, [period, anchor, reloadTick]);

  const totals = report?.totals || {};
  const before = report?.previousTotals || {};
  const picker = pickerOf(period, anchor);
  // Reports are built from UTC days: a period that has not started yet is empty.
  const atLatest = useMemo(() => shiftAnchor(period, anchor, 1) > todayAnchor(), [period, anchor]);

  const exportCsv = () => {
    setExporting(true);
    fetchReportCsv({ period, date: anchor, top: 10 })
      .then(({ blob, filename }) => {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
      })
      .catch((err) => setError(err.message || t('reports.exportError')))
      .finally(() => setExporting(false));
  };

  const periodLabel = report?.window?.label || anchor;

  return (
    <div className="ef ef-page ef-reqpage ef-reports">
      <div className="ef-reqpage__head">
        <div>
          <h1>{t('reports.title')}</h1>
          <p>{t('reports.subtitle')}</p>
        </div>
        <span style={{ flex: 1 }} />
        <button type="button" className="ef-btn" onClick={() => setReloadTick((n) => n + 1)} disabled={loading}>
          {t('common.refresh')}
        </button>
        <button type="button" className="ef-btn ef-btn--primary" onClick={exportCsv} disabled={!report || exporting}>
          <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12M7 10l5 5 5-5M5 21h14" /></svg>
          {exporting ? t('common.loading') : t('reports.export')}
        </button>
      </div>

      {error && <div className="ef-alert ef-alert--danger ef-reqpage__alert">{error}</div>}

      <div className="ef-card ef-reports__bar">
        <div className="ef-seg" role="group" aria-label={t('reports.period')}>
          {PERIODS.map((id) => (
            <button
              key={id}
              type="button"
              className={period === id ? 'is-on' : ''}
              aria-pressed={period === id}
              onClick={() => setPeriod(id)}
            >
              {t(`reports.period_${id}`)}
            </button>
          ))}
        </div>
        <div className="ef-reports__nav">
          <button type="button" className="ef-btn ef-btn--sm" onClick={() => setAnchor(shiftAnchor(period, anchor, -1))} aria-label={t('reports.previous')}>‹</button>
          <input
            className="ef-input"
            type={picker.type}
            value={picker.value}
            min={picker.type === 'number' ? 1970 : undefined}
            max={picker.type === 'number' ? new Date().getUTCFullYear() : todayAnchor().slice(0, picker.type === 'month' ? 7 : 10)}
            onChange={(event) => {
              const next = anchorOf(period, event.target.value);
              if (next) setAnchor(next);
            }}
            aria-label={t('reports.periodDate')}
          />
          <button type="button" className="ef-btn ef-btn--sm" onClick={() => setAnchor(shiftAnchor(period, anchor, 1))} disabled={atLatest} aria-label={t('reports.next')}>›</button>
          <button type="button" className="ef-btn ef-btn--sm" onClick={() => setAnchor(todayAnchor())} disabled={atLatest}>{t('reports.now')}</button>
        </div>
        <span style={{ flex: 1 }} />
        <span className="ef-muted ef-reports__range">
          {loading ? t('common.loading') : t('reports.coverage', { label: periodLabel, previous: report?.previous?.label || '—' })}
        </span>
      </div>

      {report?.truncated && (
        <div className="ef-alert ef-alert--warn ef-reqpage__alert">{t('reports.truncated')}</div>
      )}

      {report && totals.events === 0 && !loading && (
        <div className="ef-sessempty"><p>{t('reports.empty', { label: periodLabel })}</p></div>
      )}

      {report && totals.events > 0 && (
        <>
          <div className="ef-card ef-kpis">
            <Kpi label={t('reports.kpiEvents')} value={totals.events} previous={before.events} t={t} />
            <Kpi label={t('reports.kpiSessions')} value={totals.sessionsOpened} previous={before.sessionsOpened} t={t} />
            <Kpi label={t('reports.kpiSignIns')} value={totals.signIns} previous={before.signIns} t={t} />
            <Kpi label={t('reports.kpiFailures')} value={totals.failures} previous={before.failures} tone={totals.failures ? 'danger' : ''} t={t} />
            <Kpi label={t('reports.kpiAdmin')} value={totals.adminActions} previous={before.adminActions} t={t} />
            <Kpi label={t('reports.kpiActors')} value={totals.uniqueActors} previous={before.uniqueActors} t={t} />
          </div>

          <div className="ef-card ef-reports__chart">
            <div className="ef-reports__chartHead">
              <h2>{t(`reports.timeline_${report.bucketUnit}`)}</h2>
              <span className="ef-muted">{t('reports.timelineLegend')}</span>
            </div>
            <Timeline buckets={report.buckets || []} unit={report.bucketUnit} locale={locale} t={t} />
            <div className="ef-workfoot">
              <span>{t('reports.scanned', { lines: report.scannedLines, files: report.scannedFiles })}</span>
              <span style={{ flex: 1 }} />
              {report.firstEventAt && <span className="ef-mono">{report.firstEventAt} → {report.lastEventAt}</span>}
            </div>
          </div>

          <div className="ef-reports__grid">
            <div className="ef-card ef-reports__table">
              <h2>{t('reports.detailTitle')}</h2>
              <table className="ef-table">
                <thead>
                  <tr>
                    <th>{t('reports.figure')}</th>
                    <th>{periodLabel}</th>
                    <th>{report.previous?.label || '—'}</th>
                    <th>{t('reports.share')}</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ['reports.rowSessionsOpened', 'sessionsOpened'],
                    ['reports.rowSessionsClosed', 'sessionsClosed'],
                    ['reports.rowSessionsBlocked', 'sessionsBlocked'],
                    ['reports.rowSignIns', 'signIns'],
                    ['reports.rowSignInFailures', 'signInFailures'],
                    ['reports.rowAccessRequests', 'accessRequests'],
                    ['reports.rowAccessApproved', 'accessApproved'],
                    ['reports.rowAccessDenied', 'accessDenied'],
                    ['reports.rowCommandBlocks', 'commandBlocks'],
                    ['reports.rowIncidents', 'incidents'],
                    ['reports.rowAdminActions', 'adminActions'],
                    ['reports.rowFailures', 'failures'],
                    ['reports.rowActors', 'uniqueActors'],
                    ['reports.rowTargets', 'uniqueTargets']
                  ].map(([key, field]) => (
                    <tr key={field}>
                      <td>{t(key)}</td>
                      <td className="ef-mono">{totals[field] ?? 0}</td>
                      <td className="ef-mono ef-text-2">{before[field] ?? 0}</td>
                      <td className="ef-text-2">{pct(totals[field] || 0, totals.events)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <TopList title={t('reports.topActors')} items={report.topActors || []} empty={t('reports.noneYet')} />
            <TopList title={t('reports.topTargets')} items={report.topTargets || []} empty={t('reports.noneYet')} />
            <TopList title={t('reports.topEvents')} items={report.topEvents || []} empty={t('reports.noneYet')} />
          </div>
        </>
      )}

      {loading && !report && <p className="ef-muted ef-page-loading" role="status">{t('common.loading')}…</p>}
    </div>
  );
}
