import React, { useEffect, useMemo, useState } from 'react';
import ConfirmButton from '../../ui/ConfirmButton.jsx';
import { useI18n } from '../../i18n.jsx';
import { configureK8sResource, createResource, deleteResource, fetchK8sResources, updateResource } from '../../api.js';
import { describeAccessOutcome, describeResourcePolicy, normalizeRiskLevel } from '../../accessPolicy.js';
import { zoneOf } from '../MapPage.jsx';

const PROTOCOLS = ['ssh', 'rdp', 'vnc', 'http', 'https', 'agent', 'k8s'];
const DEFAULT_PORT = { ssh: 22, rdp: 3389, vnc: 5900, http: 80, https: 443, agent: 22, k8s: 443 };
const RISKS = ['low', 'medium', 'high', 'critical'];
const isWebProtocol = (protocol) => protocol === 'http' || protocol === 'https';

const splitTags = (csv) => String(csv || '').split(',').map((tag) => tag.trim()).filter(Boolean);

const formFrom = (resource) => {
  const tags = splitTags(resource?.tagsCsv);
  return {
    name: resource?.name || '',
    description: resource?.description || '',
    zone: resource ? zoneOf(resource) : '',
    otherTags: tags.filter((tag) => !tag.toLowerCase().startsWith('zone:')).join(', '),
    imageUrl: resource?.imageUrl || '',
    imageData: resource?.imageData || '',
    protocol: String(resource?.protocol || 'ssh').toLowerCase(),
    target: resource?.target || '',
    port: String(resource?.port ?? 22),
    agentProtocol: resource?.agentProtocol || 'tcp',
    tunnelTicketRateLimitMaxAttempts: String(Math.max(0, Number(resource?.tunnelTicketRateLimitMaxAttempts) || 0)),
    credentialSource: resource?.credentialSource || 'vaulted',
    sshUsername: resource?.sshUsername || '',
    sshPassword: '',
    httpUsername: resource?.httpUsername || '',
    httpPassword: '',
    k8sNamespace: 'default',
    k8sKubeconfig: '',
    riskLevel: normalizeRiskLevel(resource?.riskLevel || 'low'),
    requireAccessJustification: !!resource?.requireAccessJustification,
    requireDualApproval: !!resource?.requireDualApproval,
    enableCommandGuard: !!resource?.enableCommandGuard,
    adaptiveAccessPolicy: !!resource?.adaptiveAccessPolicy
  };
};

function Field({ id, label, hint, children, full }) {
  return (
    <div className={full ? 'ef-rfield is-full' : 'ef-rfield'}>
      <label htmlFor={id}>{label}</label>
      {children}
      {hint && <span className="ef-hint">{hint}</span>}
    </div>
  );
}

function ResourceEditor({ resource, initialProtocol, zones, onSaved, onDeleted, onClose }) {
  const { t } = useI18n();
  const isNew = !resource;
  // A new resource may start from a protocol (e.g. "Add a cluster" → Kubernetes).
  const initialForm = () => {
    const base = formFrom(resource);
    if (resource || !initialProtocol) return base;
    return { ...base, protocol: initialProtocol, port: String(DEFAULT_PORT[initialProtocol] || base.port) };
  };
  const [form, setForm] = useState(initialForm);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [newZone, setNewZone] = useState(false);

  useEffect(() => {
    setForm(initialForm());
    setError('');
    setNewZone(false);
    // The kubeconfig is never returned; only the namespace is recovered.
    if (resource && String(resource.protocol).toLowerCase() === 'k8s') {
      fetchK8sResources()
        .then((res) => {
          const cfg = (res.items || []).find((c) => c.resourceId === resource.id);
          if (cfg?.namespace) setForm((prev) => ({ ...prev, k8sNamespace: cfg.namespace }));
        })
        .catch(() => {});
    }
  }, [resource?.id]);

  const set = (key) => (event) => {
    const value = event.target.type === 'checkbox' ? event.target.checked : event.target.value;
    setForm((prev) => {
      const next = { ...prev, [key]: value };
      // Follow the protocol's usual port unless the admin typed another one.
      if (key === 'protocol' && String(prev.port) === String(DEFAULT_PORT[prev.protocol] ?? '')) next.port = String(DEFAULT_PORT[value] ?? prev.port);
      return next;
    });
  };

  const hasStoredHttpPassword = !isNew && !!String(resource?.httpUsername || '').trim();

  const preview = useMemo(() => {
    const draft = { ...form, riskLevel: form.riskLevel };
    return Array.from(new Set([...describeAccessOutcome(draft, t), ...describeResourcePolicy(draft, t)]));
  }, [form, t]);

  const save = async (event) => {
    event.preventDefault();
    const name = form.name.trim();
    const target = form.target.trim();
    if (!name || !target) {
      setError(t('resAdmin.required'));
      return;
    }
    const zone = form.zone.trim().toLowerCase();
    const tags = [zone && `zone:${zone}`, ...splitTags(form.otherTags).filter((tag) => !tag.toLowerCase().startsWith('zone:'))].filter(Boolean);
    const payload = {
      name,
      target,
      protocol: form.protocol,
      port: Number.parseInt(form.port, 10) || DEFAULT_PORT[form.protocol] || 22,
      tunnelTicketRateLimitMaxAttempts: Math.max(0, Number.parseInt(form.tunnelTicketRateLimitMaxAttempts, 10) || 0),
      description: form.description.trim(),
      imageUrl: form.imageData ? '' : form.imageUrl.trim(),
      imageData: form.imageData || '',
      tagsCsv: tags.join(','),
      credentialSource: form.credentialSource || 'vaulted',
      httpUsername: isWebProtocol(form.protocol) ? form.httpUsername.trim() : '',
      httpPassword: isWebProtocol(form.protocol) ? form.httpPassword : '',
      sshUsername: form.sshUsername.trim(),
      sshPassword: form.sshPassword,
      agentProtocol: form.protocol === 'agent' ? form.agentProtocol || 'tcp' : '',
      requireAccessJustification: !!form.requireAccessJustification,
      requireDualApproval: !!form.requireDualApproval,
      enableCommandGuard: !!form.enableCommandGuard,
      adaptiveAccessPolicy: !!form.adaptiveAccessPolicy,
      riskLevel: form.riskLevel
    };
    setBusy(true);
    setError('');
    try {
      const saved = isNew ? await createResource(payload) : await updateResource(resource.id, payload);
      if (form.protocol === 'k8s' && saved?.id) {
        try {
          await configureK8sResource(saved.id, { namespace: (form.k8sNamespace || 'default').trim(), kubeconfig: form.k8sKubeconfig || '' });
        } catch (err) {
          setError(err.message || t('resAdmin.k8sError'));
        }
      }
      onSaved(saved, isNew);
    } catch (err) {
      setError(err.message || t('resAdmin.saveError'));
    } finally {
      setBusy(false);
    }
  };

  const onImage = (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new window.FileReader();
    reader.onload = (ev) => setForm((prev) => ({ ...prev, imageData: String(ev.target.result || ''), imageUrl: '' }));
    reader.readAsDataURL(file);
  };

  const protocol = form.protocol;

  return (
    <form className="ef-card ef-redit" onSubmit={save}>
      <div className="ef-upanel__head">
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="ef-muted" style={{ fontSize: 12 }}>{isNew ? t('resAdmin.newResource') : t('map.resource')}</div>
          <div className="ef-insp__title ef-mono">{form.name || '—'}</div>
        </div>
        <button type="button" className="ef-btn ef-btn--sm" onClick={onClose}>{t('common.close')}</button>
      </div>

      <section className="ef-rsec">
        <h3>{t('resAdmin.identity')}</h3>
        <div className="ef-rgrid">
          <Field id="r-name" label={t('resAdmin.name')}>
            <input id="r-name" className="ef-input ef-mono" value={form.name} onChange={set('name')} required />
          </Field>
          <Field id="r-zone" label={t('zones.zone')}>
            {newZone ? (
              <input id="r-zone" className="ef-input ef-mono" value={form.zone} onChange={set('zone')} placeholder="prod" autoFocus />
            ) : (
              <select
                id="r-zone"
                className="ef-input"
                value={form.zone}
                onChange={(event) => {
                  if (event.target.value === '__new__') {
                    setNewZone(true);
                    setForm((prev) => ({ ...prev, zone: '' }));
                  } else {
                    set('zone')(event);
                  }
                }}
              >
                <option value="">{t('map.noZone')}</option>
                {zones.map((zone) => <option key={zone} value={zone}>{zone}</option>)}
                <option value="__new__">{t('resAdmin.newZoneOption')}</option>
              </select>
            )}
          </Field>
          <Field id="r-desc" label={t('resAdmin.description')} full>
            <input id="r-desc" className="ef-input" value={form.description} onChange={set('description')} />
          </Field>
          <Field id="r-tags" label={t('resAdmin.otherTags')} hint={t('resAdmin.tagsHint')} full>
            <input id="r-tags" className="ef-input ef-mono" value={form.otherTags} onChange={set('otherTags')} placeholder="db, linux" />
          </Field>
          <Field id="r-image" label={t('resAdmin.image')} full>
            <div className="ef-rimage">
              {(form.imageData || form.imageUrl) && <img src={form.imageData || form.imageUrl} alt="" />}
              {!form.imageData && <input id="r-image" className="ef-input" value={form.imageUrl} onChange={set('imageUrl')} placeholder="https://…" />}
              <label className="ef-btn ef-btn--sm ef-rimage__upload">
                {t('resAdmin.upload')}
                <input type="file" accept="image/*" onChange={onImage} hidden />
              </label>
              {form.imageData && <button type="button" className="ef-btn ef-btn--sm" onClick={() => setForm((prev) => ({ ...prev, imageData: '' }))}>{t('resAdmin.removeImage')}</button>}
            </div>
          </Field>
        </div>
      </section>

      <section className="ef-rsec">
        <h3>{t('resAdmin.connection')}</h3>
        <div className="ef-rgrid">
          <Field id="r-proto" label={t('sess.protocol')}>
            <select id="r-proto" className="ef-input" value={protocol} onChange={set('protocol')}>
              {PROTOCOLS.map((value) => <option key={value} value={value}>{t(`resAdmin.protocols.${value}`)}</option>)}
            </select>
          </Field>
          <Field id="r-port" label={t('resAdmin.port')}>
            <input id="r-port" className="ef-input ef-mono" type="number" min="1" max="65535" value={form.port} onChange={set('port')} />
          </Field>
          <Field id="r-target" label={protocol === 'k8s' ? t('resAdmin.clusterLabel') : t('map.address')} hint={protocol === 'k8s' ? t('resAdmin.k8sTargetHint') : null} full>
            <input id="r-target" className="ef-input ef-mono" value={form.target} onChange={set('target')} placeholder={protocol === 'k8s' ? 'k8s.prod' : '10.0.0.12'} required />
          </Field>
          {protocol === 'agent' && (
            <>
              <Field id="r-aproto" label={t('resAdmin.tunneled')}>
                <select id="r-aproto" className="ef-input" value={form.agentProtocol} onChange={set('agentProtocol')}>
                  {['tcp', 'ssh', 'rdp', 'vnc', 'http', 'https'].map((value) => <option key={value} value={value}>{value}</option>)}
                </select>
              </Field>
              <Field id="r-auser" label={t('resAdmin.agentUser')}>
                <input id="r-auser" className="ef-input ef-mono" value={form.sshUsername} onChange={set('sshUsername')} autoComplete="off" />
              </Field>
            </>
          )}
          {(protocol === 'agent' || protocol === 'rdp') && (
            <Field id="r-rate" label={t('resAdmin.ticketLimit')} hint={t('resAdmin.ticketLimitHint')}>
              <input id="r-rate" className="ef-input ef-mono" type="number" min="0" value={form.tunnelTicketRateLimitMaxAttempts} onChange={set('tunnelTicketRateLimitMaxAttempts')} />
            </Field>
          )}
        </div>
      </section>

      {(protocol === 'ssh' || isWebProtocol(protocol) || protocol === 'k8s') && (
        <section className="ef-rsec">
          <h3>{t('resAdmin.credentials')}</h3>
          <div className="ef-rgrid">
            {protocol === 'ssh' && (
              <>
                <Field id="r-csrc" label={t('resAdmin.credentialMode')} full>
                  <select id="r-csrc" className="ef-input" value={form.credentialSource} onChange={set('credentialSource')}>
                    {['vaulted', 'brokered', 'ephemeral_account'].map((value) => <option key={value} value={value}>{t(`resAdmin.modes.${value}`)}</option>)}
                  </select>
                </Field>
                <Field id="r-suser" label={t('resAdmin.account')}>
                  <input id="r-suser" className="ef-input ef-mono" value={form.sshUsername} onChange={set('sshUsername')} placeholder="root" autoComplete="off" />
                </Field>
                <Field id="r-spass" label={t('resAdmin.secret')} hint={!isNew && resource?.hasCredentials ? t('resAdmin.keepSecret') : null}>
                  <input id="r-spass" className="ef-input" type="password" value={form.sshPassword} onChange={set('sshPassword')} autoComplete="new-password" placeholder={!isNew && resource?.hasCredentials ? '••••••••' : ''} />
                </Field>
              </>
            )}
            {isWebProtocol(protocol) && (
              <>
                <Field id="r-huser" label={t('resAdmin.httpAccount')}>
                  <input id="r-huser" className="ef-input ef-mono" value={form.httpUsername} onChange={set('httpUsername')} autoComplete="off" />
                </Field>
                <Field id="r-hpass" label={t('resAdmin.httpPassword')} hint={hasStoredHttpPassword ? t('resAdmin.keepSecret') : null}>
                  <input id="r-hpass" className="ef-input" type="password" value={form.httpPassword} onChange={set('httpPassword')} autoComplete="new-password" placeholder={hasStoredHttpPassword ? '••••••••' : ''} />
                </Field>
              </>
            )}
            {protocol === 'k8s' && (
              <>
                <Field id="r-ns" label={t('resAdmin.namespace')}>
                  <input id="r-ns" className="ef-input ef-mono" value={form.k8sNamespace} onChange={set('k8sNamespace')} />
                </Field>
                <Field id="r-kube" label="kubeconfig" hint={isNew ? t('resAdmin.kubeHint') : t('resAdmin.kubeKeep')} full>
                  <textarea id="r-kube" className="ef-input ef-mono ef-rtextarea" rows={5} value={form.k8sKubeconfig} onChange={set('k8sKubeconfig')} placeholder={'apiVersion: v1\nkind: Config'} />
                </Field>
              </>
            )}
          </div>
        </section>
      )}

      <section className="ef-rsec">
        <h3>{t('resAdmin.rules')}</h3>
        <div className="ef-rgrid">
          <Field id="r-risk" label={t('map.riskLabel')}>
            <select id="r-risk" className="ef-input" value={form.riskLevel} onChange={set('riskLevel')}>
              {RISKS.map((value) => <option key={value} value={value}>{t(`map.risk.${value}`)}</option>)}
            </select>
          </Field>
          <div className="ef-rchecks is-full">
            <label className="ef-check"><input type="checkbox" checked={form.requireAccessJustification} onChange={set('requireAccessJustification')} />{t('resAdmin.justification')}</label>
            <label className="ef-check"><input type="checkbox" checked={form.requireDualApproval} onChange={set('requireDualApproval')} />{t('resAdmin.dualApproval')}</label>
            {(protocol === 'ssh' || (protocol === 'agent' && form.agentProtocol === 'ssh')) && (
              <label className="ef-check"><input type="checkbox" checked={form.enableCommandGuard} onChange={set('enableCommandGuard')} />{t('resAdmin.commandGuard')}</label>
            )}
            <label className="ef-check"><input type="checkbox" checked={form.adaptiveAccessPolicy} onChange={set('adaptiveAccessPolicy')} />{t('resAdmin.adaptive')}</label>
          </div>
        </div>
        {preview.length > 0 && (
          <div className="ef-rpreview">
            <span className="ef-muted">{t('resAdmin.preview')}</span>
            <ul className="ef-conds">{preview.map((item) => <li key={item}>{item}</li>)}</ul>
            {form.zone && <p className="ef-hint" style={{ margin: '6px 0 0' }}>{t('resAdmin.zoneRulesToo', { zone: form.zone })}</p>}
          </div>
        )}
      </section>

      {error && <div className="ef-alert ef-alert--danger" style={{ margin: '0 16px 12px' }}>{error}</div>}
      <div className="ef-upanel__foot">
        {!isNew && (
          <ConfirmButton
            confirmLabel={t('resAdmin.confirmDelete')}
            disabled={busy}
            onConfirm={async () => {
              setBusy(true);
              try {
                await deleteResource(resource.id);
                onDeleted(resource.id);
              } catch (err) {
                setError(err.message || t('resAdmin.deleteError'));
              } finally {
                setBusy(false);
              }
            }}
          >
            {t('common.delete')}
          </ConfirmButton>
        )}
        <span style={{ flex: 1 }} />
        <button type="button" className="ef-btn" onClick={onClose}>{t('common.cancel')}</button>
        <button type="submit" className="ef-btn ef-btn--primary" disabled={busy}>{isNew ? t('resAdmin.create') : t('common.save')}</button>
      </div>
    </form>
  );
}

export default function ResourcesAdmin({ resources, loading, focusId, onFocusUsed, onResourcesChange, onOpenMap }) {
  const { t } = useI18n();
  const [query, setQuery] = useState('');
  const [zoneFilter, setZoneFilter] = useState('all');
  const [selectedId, setSelectedId] = useState(null);
  const [creating, setCreating] = useState(false);
  const [notice, setNotice] = useState('');
  const [newProtocol, setNewProtocol] = useState('');

  // focusId is a resource id to edit, or "new" / "new:<protocol>" to start a new one.
  useEffect(() => {
    if (!focusId) return;
    if (String(focusId).startsWith('new')) {
      setNewProtocol(String(focusId).split(':')[1] || '');
      setSelectedId(null);
      setCreating(true);
    } else {
      setSelectedId(focusId);
      setCreating(false);
    }
    onFocusUsed?.();
  }, [focusId]);

  const zones = useMemo(() => Array.from(new Set(resources.map(zoneOf).filter(Boolean))).sort(), [resources]);

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    const map = new Map();
    resources
      .filter((r) => zoneFilter === 'all' || zoneOf(r) === zoneFilter)
      .filter((r) => !q || [r.name, r.target, r.tagsCsv, r.protocol, r.description].some((v) => String(v || '').toLowerCase().includes(q)))
      .sort((a, b) => String(a.name).localeCompare(String(b.name)))
      .forEach((resource) => {
        const zone = zoneOf(resource);
        if (!map.has(zone)) map.set(zone, []);
        map.get(zone).push(resource);
      });
    return Array.from(map.entries()).sort(([a], [b]) => (a === '' ? 1 : b === '' ? -1 : a.localeCompare(b)));
  }, [resources, query, zoneFilter]);

  const selected = resources.find((r) => r.id === selectedId) || null;
  const editorOpen = creating || !!selected;

  const credentialLabel = (resource) => {
    const protocol = String(resource.protocol || '').toLowerCase();
    if (protocol === 'ssh') return resource.hasCredentials ? t(`resAdmin.modesShort.${resource.credentialSource || 'vaulted'}`) : t('resAdmin.typedAtLogin');
    if (isWebProtocol(protocol)) return resource.httpUsername ? t('resAdmin.httpAccountShort') : '—';
    if (protocol === 'k8s') return 'kubeconfig';
    return '—';
  };

  return (
    <div className="ef ef-adminpage">
      <div className="ef-reqpage__head">
        <div>
          <h1>{t('resAdmin.title')}</h1>
          <p>{t('resAdmin.subtitle', { count: resources.length, zones: zones.length })}</p>
        </div>
        <span style={{ flex: 1 }} />
        <button type="button" className="ef-btn" onClick={onOpenMap}>{t('resAdmin.seeMap')}</button>
        <button type="button" className="ef-btn ef-btn--primary" onClick={() => { setNewProtocol(''); setCreating(true); setSelectedId(null); setNotice(''); }}>
          <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
          {t('resAdmin.newResource')}
        </button>
      </div>
      {notice && <div className="ef-alert ef-reqpage__alert">{notice}</div>}

      <div className="ef-reqpage__grid">
        <div className={editorOpen ? 'ef-card ef-ulist ef-rlist is-narrow' : 'ef-card ef-ulist ef-rlist'}>
          <div className="ef-toolbar ef-journal__bar">
            <label className="ef-search ef-search--sm">
              <svg className="ef-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" /></svg>
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('map.searchPlaceholder')} aria-label={t('map.search')} />
            </label>
            <select className="ef-input ef-journal__select" value={zoneFilter} onChange={(event) => setZoneFilter(event.target.value)} aria-label={t('zones.zone')}>
              <option value="all">{t('map.allZones')}</option>
              {zones.map((zone) => <option key={zone} value={zone}>{zone}</option>)}
              <option value="">{t('map.noZone')}</option>
            </select>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="ef-table">
              <thead>
                <tr>
                  <th>{t('map.resource')}</th>
                  <th>{t('map.address')}</th>
                  <th>{t('map.type')}</th>
                  <th>{t('map.riskLabel')}</th>
                  {!editorOpen && <th>{t('resAdmin.rulesShort')}</th>}
                  {!editorOpen && <th>{t('map.credentials')}</th>}
                </tr>
              </thead>
              <tbody>
                {groups.map(([zone, items]) => (
                  <React.Fragment key={zone || 'none'}>
                    <tr className="ef-table__group"><td colSpan={editorOpen ? 4 : 6}><strong>{zone || t('map.noZone')}</strong> <span className="ef-muted">· {t('map.resourceCount', { count: items.length })}</span></td></tr>
                    {items.map((resource) => {
                      const risk = normalizeRiskLevel(resource.riskLevel);
                      const rules = [
                        resource.requireDualApproval && t('resAdmin.badgeApproval'),
                        resource.requireAccessJustification && t('resAdmin.badgeReason'),
                        resource.enableCommandGuard && t('resAdmin.badgeGuard')
                      ].filter(Boolean);
                      return (
                        <tr key={resource.id} className={selectedId === resource.id ? 'is-selected' : undefined} onClick={() => { setSelectedId(resource.id); setCreating(false); setNotice(''); }}>
                          <td className="ef-mono">{resource.name}</td>
                          <td className="ef-mono ef-text-2">{resource.target}:{resource.port}</td>
                          <td className="ef-mono ef-text-2">{String(resource.protocol || '').toUpperCase()}</td>
                          <td><span className={`ef-badge ef-badge--${risk}`}>{t(`map.risk.${risk}`)}</span></td>
                          {!editorOpen && <td>{rules.length ? rules.map((r) => <span key={r} className="ef-badge" style={{ marginRight: 4 }}>{r}</span>) : <span className="ef-muted">{t('resAdmin.direct')}</span>}</td>}
                          {!editorOpen && <td className="ef-text-2">{credentialLabel(resource)}</td>}
                        </tr>
                      );
                    })}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
            {!groups.length && <div className="ef-sessempty"><p>{loading ? t('common.loading') : t('resAdmin.empty')}</p></div>}
          </div>
        </div>

        {editorOpen && (
          <ResourceEditor
            resource={creating ? null : selected}
            initialProtocol={creating ? newProtocol : ''}
            zones={zones}
            onClose={() => { setCreating(false); setSelectedId(null); }}
            onSaved={(saved, isNew) => {
              onResourcesChange((prev) => (isNew ? [...prev, saved] : prev.map((item) => (item.id === saved.id ? saved : item))));
              setCreating(false);
              setSelectedId(saved.id);
              setNotice(isNew ? t('resAdmin.created', { name: saved.name }) : t('resAdmin.saved', { name: saved.name }));
            }}
            onDeleted={(id) => {
              const name = resources.find((r) => r.id === id)?.name || '';
              onResourcesChange((prev) => prev.filter((item) => item.id !== id));
              setSelectedId(null);
              setNotice(t('resAdmin.deleted', { name }));
            }}
          />
        )}
      </div>
    </div>
  );
}
