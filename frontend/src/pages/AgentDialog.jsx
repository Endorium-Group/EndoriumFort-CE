import React from 'react';
import { useI18n } from '../i18n.jsx';
import Dialog from '../ui/Dialog.jsx';
import CopyButton from '../ui/CopyButton.jsx';

// Opens a resource through the native agent: the browser hands an
// endoriumfort:// link to the agent, which opens a local tunnel.
export default function AgentDialog({ modal, onLaunch, onNewPort, onClose }) {
  const { t } = useI18n();
  const { resource } = modal;
  const protocol = String(resource?.protocol === 'agent' ? resource?.agentProtocol || 'tcp' : resource?.protocol || '').toUpperCase();

  return (
    <Dialog
      kicker={t('agentDlg.kicker', { protocol })}
      title={t('agentDlg.title', { name: resource.name })}
      subtitle={<span className="ef-mono">{resource.target}:{resource.port}</span>}
      onClose={onClose}
      width={560}
      footer={
        <>
          <button type="button" className="ef-btn" onClick={onNewPort}>{t('agentDlg.newPort')}</button>
          <span className="ef-dlg__spacer" />
          <button type="button" className="ef-btn" onClick={onClose}>{t('common.close')}</button>
          <button type="button" className="ef-btn ef-btn--primary" onClick={() => onLaunch(modal.deepLink)} disabled={!modal.deepLink || modal.launchState === 'opening'}>
            {modal.launchState === 'opening' ? t('agentDlg.opening') : t('agentDlg.open')}
          </button>
        </>
      }
    >
      <dl className="ef-kv ef-agentkv">
        <dt>{t('agentDlg.local')}</dt>
        <dd className="ef-mono">127.0.0.1:{modal.port}</dd>
        <dt>{t('agentDlg.then')}</dt>
        <dd>
          {modal.openInBrowser
            ? <>{t('agentDlg.thenBrowser')} <a href={modal.localUrl} target="_blank" rel="noreferrer" className="ef-mono">{modal.localUrl}</a></>
            : t('agentDlg.thenClient', { protocol, endpoint: modal.localEndpoint || `127.0.0.1:${modal.port}` })}
        </dd>
      </dl>

      {modal.launchState === 'opened' && (
        <div className="ef-alert ef-dlg__error" style={{ marginTop: 12 }}>{t('agentDlg.opened')}</div>
      )}
      {modal.launchState === 'fallback' && (
        <div className="ef-alert ef-alert--warn ef-dlg__error is-stack" style={{ marginTop: 12 }}>
          {t('agentDlg.noAgent', { platform: modal.installGuide?.platform || '' })}
          <div className="ef-agentcmd">
            <code className="ef-mono">{modal.installGuide?.command}</code>
            <CopyButton text={modal.installGuide?.command} label={t('agentDlg.copy')} />
          </div>
        </div>
      )}

      <details className="ef-agentmore">
        <summary>{t('agentDlg.manual')}</summary>
        <p className="ef-hint">{t('agentDlg.manualHint')}</p>
        <div className="ef-agentcmd">
          <code className="ef-mono">{modal.command}</code>
          <CopyButton text={modal.command} label={t('agentDlg.copy')} />
        </div>
        <p className="ef-hint">{t('agentDlg.linkHint')}</p>
        <div className="ef-agentcmd">
          <code className="ef-mono">{modal.deepLink}</code>
          <CopyButton text={modal.deepLink} label={t('agentDlg.copy')} />
        </div>
      </details>
    </Dialog>
  );
}
