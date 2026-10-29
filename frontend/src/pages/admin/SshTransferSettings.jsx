// EndoriumFort — SSH file transfer settings card.
//
// Shown in Administration › Security. The per-resource switches (download /
// upload, off by default) live in the resource editor; this card holds the
// bastion-wide limit, served by the settings catalog (group "ssh").
import React, { useEffect, useState } from 'react';
import { useI18n } from '../../i18n.jsx';
import { fetchIntegrationSettings } from '../../api.js';
import SettingsGroup from '../../ui/SettingsGroup.jsx';

export default function SshTransferSettings() {
  const { t } = useI18n();
  const [items, setItems] = useState(null);
  const [error, setError] = useState('');

  const load = async () => {
    try {
      const data = await fetchIntegrationSettings();
      setItems(Array.isArray(data?.items) ? data.items : []);
      setError('');
    } catch (err) {
      setError(err.message || t('sshTransfer.loadError'));
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <section className="ef-card" style={{ marginTop: 16 }}>
      <div className="ef-enroll__head"><h2 className="ef-sectitle">{t('sshTransfer.settingsTitle')}</h2></div>
      <div style={{ padding: '12px 16px' }}>
        <p className="ef-hint" style={{ marginTop: 0 }}>{t('sshTransfer.settingsHint')}</p>
        {error && <div className="ef-alert ef-alert--danger">{error}</div>}
        {items && <SettingsGroup group="ssh" items={items} onSaved={load} />}
      </div>
    </section>
  );
}
