import { useEffect, useState } from 'react';

// A session's `user` is the account used on the target (e.g. postgres-admin),
// not necessarily the EndoriumFort operator. The server sends the operator (the
// subject of the access grant); older servers did not, so fall back to the
// grant or the actor of the session.create audit event.
export function withOperators(sessions, accessGrants, auditItems) {
  const grantById = new Map((accessGrants || []).map((grant) => [Number(grant.id), grant]));
  const creatorBySession = new Map();
  (auditItems || []).forEach((item) => {
    if (item?.type !== 'session.create' || !item.payloadIsJson) return;
    try {
      const payload = JSON.parse(item.payloadRaw || '{}');
      const id = Number(payload.sessionId || payload.id) || 0;
      if (id && item.actor) creatorBySession.set(id, item.actor);
    } catch (_) {
      // Unreadable payload: fall back to the session account below.
    }
  });
  return (sessions || []).map((session) => {
    const grant = grantById.get(Number(session.accessGrantId)) || null;
    return {
      ...session,
      grant,
      operator: session.operator || grant?.subject || creatorBySession.get(Number(session.id)) || session.user
    };
  });
}

// Time window of a time-limited session, or null when it has no limit.
export function privilegeWindow(session, now) {
  const seconds = Number(session?.maxDurationSeconds) || 0;
  const start = Date.parse(session?.createdAt || '');
  if (seconds <= 0 || Number.isNaN(start)) return null;
  const total = seconds * 1000;
  const expiresAt = new Date(start + total);
  const remaining = expiresAt.getTime() - now;
  return { expiresAt, remaining, ratio: remaining / total };
}

export function useNow(intervalMs = 30000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}

export const initialsOf = (name) => String(name || '?').replace(/[^a-z0-9]/gi, '').slice(0, 2).toUpperCase() || '?';

export const formatRemaining = (ms) => {
  const totalMinutes = Math.max(0, Math.floor(ms / 60000));
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return hours > 0 ? `${hours} h ${String(minutes).padStart(2, '0')}` : `${minutes} min`;
};

export const formatClock = (date, locale) =>
  date.toLocaleTimeString(locale === 'fr' ? 'fr-FR' : 'en-GB', { hour: '2-digit', minute: '2-digit' });

// "09:40" today, "6 oct. 09:40" otherwise.
export const formatWhen = (value, locale) => {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  const tag = locale === 'fr' ? 'fr-FR' : 'en-GB';
  const time = formatClock(date, locale);
  if (date.toDateString() === new Date().toDateString()) return time;
  return `${date.toLocaleDateString(tag, { day: 'numeric', month: 'short' })} ${time}`;
};

// "il y a 25 min" / "25 min ago".
export const formatAgo = (value, now, locale) => {
  const time = Date.parse(value || '');
  if (Number.isNaN(time)) return '';
  const rtf = new Intl.RelativeTimeFormat(locale === 'fr' ? 'fr' : 'en', { numeric: 'auto' });
  const minutes = Math.round((time - now) / 60000);
  if (Math.abs(minutes) < 60) return rtf.format(minutes, 'minute');
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 48) return rtf.format(hours, 'hour');
  return rtf.format(Math.round(hours / 24), 'day');
};

export const formatDuration = (ms, locale) => {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const totalMinutes = Math.floor(ms / 60000);
  if (totalMinutes < 60) return `${Math.max(1, totalMinutes)} min`;
  const hours = Math.floor(totalMinutes / 60);
  if (hours < 48) return `${hours} h ${String(totalMinutes % 60).padStart(2, '0')}`;
  return `${Math.floor(hours / 24)} ${locale === 'fr' ? 'j' : 'd'}`;
};
