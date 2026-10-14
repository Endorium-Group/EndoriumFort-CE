import React from 'react';
import { useI18n } from '../i18n.jsx';
import Dialog from './Dialog.jsx';
import { LockIcon } from './RelayLock.jsx';

// Server feature keys (license gates) → module names shown on the License page.
const FEATURE_MODULE = {
  'jit.governance': 'jit',
  recording: 'recording',
  'rbi.recording': 'recording',
  'rbi.transfer': 'recording',
  relay: 'relays',
  relays: 'relays',
  k8s: 'k8s',
  'session.dna': 'evidence',
  'evidence.packs': 'evidence',
  'vault.dynamic': 'vault',
  'vault.rotation': 'vault',
  siem: 'integrations',
  itsm: 'integrations',
  scim: 'integrations',
  sso: 'integrations',
  ldap: 'integrations',
  itdr: 'itdr',
  'security.center': 'securityCenter',
  containment: 'securityCenter',
  cluster: 'cluster'
};

// Opened when a premium route answers 403 or a locked entry is clicked.
// `feature` is either a server key ("jit.governance") or an already readable label.
export default function UpsellDialog({ feature, requiredTier, community, canManage, onOpenLicense, onClose }) {
  const { t } = useI18n();
  const module = FEATURE_MODULE[String(feature || '').toLowerCase()];
  const label = module ? t(`license.mods.${module}`) : feature || t('dlg.upsell.thisFeature');
  const tier = t(`license.tiers.${requiredTier === 'enterprise' ? 'enterprise' : 'pro'}`);

  return (
    <Dialog
      title={t('dlg.upsell.title')}
      onClose={onClose}
      width={420}
      footer={
        <>
          <span className="ef-dlg__spacer" />
          <button type="button" className="ef-btn" onClick={onClose}>{t('common.close')}</button>
          {!community && canManage && (
            <button type="button" className="ef-btn ef-btn--primary" onClick={onOpenLicense}>{t('dlg.upsell.openLicense')}</button>
          )}
        </>
      }
    >
      <span className="ef-dlg__lock"><LockIcon size={16} /></span>
      <p style={{ margin: '0 0 6px' }}>{t('dlg.upsell.body', { feature: label, tier })}</p>
      <p className="ef-hint" style={{ margin: 0 }}>
        {community ? t('dlg.upsell.community') : canManage ? t('dlg.upsell.admin') : t('dlg.upsell.askAdmin')}
      </p>
    </Dialog>
  );
}
