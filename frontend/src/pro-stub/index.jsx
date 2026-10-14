// EndoriumFort — Community Edition stub for the `@pro` overlay.
//
// The premium UI is physically absent from the Community build; the `@pro` Vite
// alias resolves here (src/pro/ is not shipped in the public core). These no-op
// components keep imports valid. Premium tabs/sections are already gated in
// App.jsx (locked → upsell modal), so in CE these never actually render — and
// their heavy dependencies (e.g. @novnc) never enter the CE bundle.
import React from 'react';
import { useI18n } from '../i18n.jsx';

export function VncViewerModal() {
  return null;
}

// Evidence & replay page: the Community build only explains what the section is.
export function EvidencePage({ onUnlock }) {
  const { t } = useI18n();
  return (
    <div className="ef ef-page ef-reqpage">
      <section className="ef-card ef-soon">
        <h1>{t('shell.evidence')}</h1>
        <p>{t('evidence.locked')}</p>
        <button type="button" className="ef-btn" onClick={() => onUnlock?.(t('shell.evidence'), 'pro')}>{t('req.unlock')}</button>
      </section>
    </div>
  );
}

export function JitPage() {
  return null;
}

export function RelaysPage() {
  return null;
}

export function VaultPage() {
  return null;
}

export function ThreatsPage() {
  return null;
}

export function IntegrationsPage() {
  return null;
}

export function AppearancePage() {
  return null;
}

export function KubernetesPage() {
  return null;
}

export const proEdition = 'community';
