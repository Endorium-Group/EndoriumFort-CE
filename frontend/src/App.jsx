import { useEffect, useMemo, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import QRCode from 'qrcode';
import {
  changePassword,
  fetchHealth,
  fetchBranding,
  createSession,
  deleteUser,
  disable2FA,
  fetchBootstrapStatus,
  fetchAudit,
  fetchContainmentStatus,
  fetchActiveSecurityIncident,
  openSecurityIncident,
  closeSecurityIncident,
  reportSecurityIncidentEscalation,
  fetchSecurityAlerts,
  issueEphemeralCredential,
  consumeEphemeralCredential,
  previewSessionRisk,
  fetchLicenseStatus,
  applyLicense,
  reloadLicense,
  mintAgentToken,
  fetchResources,
  fetchSessions,
  fetchStats,
  fetchUsers,
  get2FAStatus,
  login,
  logout,
  startOidcSso,
  fetchSsoLoginOptions,
  setAuthToken,
  setup2FA,
  terminateSession,
  updateUser,
  createUser,
  verify2FA,
  fetchAccessRequests,
  createAccessRequest,
  approveAccessRequest,
  denyAccessRequest,
  setContainmentMode,
  fetchRelayResolution,
  beginWebAuthnRegistration,
  verifyWebAuthnRegistration,
  deleteWebAuthnCredential,
  setMfaPreference,
  fetchAccessProfiles,
  fetchAccessGrants,
} from './api.js';
import LoginPage from './pages/LoginPage.jsx';
import MapPage from './pages/MapPage.jsx';
import SessionsPage from './pages/SessionsPage.jsx';
import RequestsPage from './pages/RequestsPage.jsx';
import JournalPage from './pages/JournalPage.jsx';
import ZonesPage from './pages/ZonesPage.jsx';
import UsersAdmin from './pages/admin/UsersAdmin.jsx';
import ResourcesAdmin from './pages/admin/ResourcesAdmin.jsx';
import SecurityAdmin from './pages/admin/SecurityAdmin.jsx';
import MfaCard from './pages/account/MfaCard.jsx';
import LicenseAdmin from './pages/admin/LicenseAdmin.jsx';
import AccountPage from './pages/account/AccountPage.jsx';
import FirstLoginDialog from './pages/account/FirstLoginDialog.jsx';
import AccessDialog from './pages/AccessDialog.jsx';
import UpsellDialog from './ui/UpsellDialog.jsx';
import Dialog from './ui/Dialog.jsx';
import LiveAlerts from './ui/LiveAlerts.jsx';
import IncidentBanner from './ui/IncidentBanner.jsx';
import LicenseBar from './ui/LicenseBar.jsx';
import AgentDialog from './pages/AgentDialog.jsx';
import AdminLayout from './layout/AdminLayout.jsx';

import { withOperators } from './ui/sessions.js';
import { versionText } from './ui/version.js';
import { applyBranding } from './ui/branding.js';
import AppShell, { SHELL_TABS, tabForPath } from './layout/AppShell.jsx';
import GettingStarted from './ui/GettingStarted.jsx';
import { EmptyState, SectionCard } from './components/ui/primitives.jsx';
import { useI18n } from './i18n.jsx';
// Premium UI comes from the `@pro` overlay: real components in the EE build
// (src/pro/), no-op stubs in the CE build (src/pro-stub/). See vite.config.js.
import { AppearancePage, EvidencePage, IntegrationsPage, JitPage, KubernetesPage, RelaysPage, ThreatsPage, VaultPage, VncViewerModal } from '@pro';
// Remote Browser Isolation viewer — core feature (present in CE too).
import RbiViewerModal from './RbiViewerModal.jsx';

// SSH session whose terminal this tab has open, so a reload can resume it.
// Per tab (sessionStorage): another tab must not grab the same shell.
const OPEN_TERMINAL_KEY = 'endoriumfort_open_terminal';
const readOpenTerminal = () => {
  try { return Number(sessionStorage.getItem(OPEN_TERMINAL_KEY)) || 0; } catch (_) { return 0; }
};
const rememberOpenTerminal = (sessionId) => {
  try { sessionStorage.setItem(OPEN_TERMINAL_KEY, String(sessionId)); } catch (_) { /* storage unavailable */ }
};
const forgetOpenTerminal = () => {
  try { sessionStorage.removeItem(OPEN_TERMINAL_KEY); } catch (_) { /* storage unavailable */ }
};

const normalizeRole = (role) => {
  const value = String(role || '').toLowerCase();
  if (value === 'platform_admin' || value === 'access_admin') return 'admin';
  if (value === 'session_operator') return 'operator';
  if (value === 'security_auditor' || value === 'security_analyst') return 'auditor';
  return value || 'operator';
};

const roleLabel = (role, t) => {
  const mapped = normalizeRole(role);
  if (!t) return mapped;
  const label = t(`roles.${mapped}.label`);
  return label !== `roles.${mapped}.label` ? label : mapped;
};

const isWebAuthnSupported = () =>
  typeof window !== 'undefined' &&
  typeof window.PublicKeyCredential !== 'undefined' &&
  typeof navigator !== 'undefined' &&
  !!navigator.credentials?.create &&
  !!navigator.credentials?.get;

const decodeBase64Url = (value) => {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const binary = window.atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const encodeBase64Url = (value) => {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value || []);
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const serializeAuthenticatorTransports = (response) => {
  if (!response || typeof response.getTransports !== 'function') return [];
  try {
    const transports = response.getTransports();
    return Array.isArray(transports) ? transports : [];
  } catch (_) {
    return [];
  }
};

const createBrowserPasskey = async (options) => {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not available in this browser.');
  }
  const publicKey = {
    ...options.publicKey,
    challenge: decodeBase64Url(options.publicKey.challenge),
    user: {
      ...options.publicKey.user,
      id: decodeBase64Url(options.publicKey.user.id)
    },
    excludeCredentials: (options.publicKey.excludeCredentials || []).map((item) => ({
      ...item,
      id: decodeBase64Url(item.id)
    }))
  };
  const credential = await navigator.credentials.create({ publicKey });
  if (!credential || !credential.response || typeof credential.response.getPublicKey !== 'function') {
    throw new Error('This browser did not return a usable WebAuthn public key.');
  }
  const publicKeyBuffer = credential.response.getPublicKey();
  const authenticatorData = credential.response.getAuthenticatorData?.();
  if (!publicKeyBuffer || !authenticatorData) {
    throw new Error('Unable to extract WebAuthn registration data from this browser.');
  }
  return {
    credentialId: credential.id,
    publicKey: encodeBase64Url(new Uint8Array(publicKeyBuffer)),
    algorithm: credential.response.getPublicKeyAlgorithm?.() || 0,
    authenticatorData: encodeBase64Url(new Uint8Array(authenticatorData)),
    clientDataJSON: encodeBase64Url(new Uint8Array(credential.response.clientDataJSON)),
    transports: serializeAuthenticatorTransports(credential.response)
  };
};

const getBrowserPasskeyAssertion = async (options) => {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not available in this browser.');
  }
  const publicKey = {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((item) => ({
      ...item,
      id: decodeBase64Url(item.id)
    }))
  };
  const credential = await navigator.credentials.get({ publicKey });
  if (!credential || !credential.response) {
    throw new Error('No passkey assertion was returned by the browser.');
  }
  return {
    credentialId: credential.id,
    authenticatorData: encodeBase64Url(new Uint8Array(credential.response.authenticatorData)),
    clientDataJSON: encodeBase64Url(new Uint8Array(credential.response.clientDataJSON)),
    signature: encodeBase64Url(new Uint8Array(credential.response.signature))
  };
};

const CAPABILITY_PERMISSION_MAP = {
  manageResources: ['resources.manage'],
  viewAudit: ['audit.read'],
  viewRecordings: ['recordings.read'],
  operateSessions: ['sessions.create', 'sessions.read'],
  viewStats: ['stats.read']
};

const hasRoleCapabilityFallback = (role, capability) => {
  const mapped = normalizeRole(role);
  if (mapped === 'admin') return true;
  if (mapped === 'operator') {
    return ['operateSessions', 'viewStats'].includes(capability);
  }
  if (mapped === 'auditor') {
    return ['viewAudit', 'viewRecordings', 'viewStats'].includes(capability);
  }
  return false;
};

const hasCapability = (role, permissions, capability) => {
  const required = CAPABILITY_PERMISSION_MAP[capability] || [];
  if (Array.isArray(permissions) && permissions.length) {
    return required.some((permission) => permissions.includes(permission) || permissions.includes('*'));
  }
  return hasRoleCapabilityFallback(role, capability);
};

const LIVE_ALERT_SEVERITY_WEIGHT = {
  critical: 3,
  warning: 2,
  ok: 1
};

const LIVE_ALERT_COOLDOWN_MS = {
  critical: 0,
  warning: 45000,
  ok: 120000
};

const LIVE_ALERT_PROFILES = {
  strict: {
    cooldownMultiplier: 1.8,
    maxVisible: { critical: 2, warning: 2, ok: 1, total: 4 }
  },
  normal: {
    cooldownMultiplier: 1,
    maxVisible: { critical: 2, warning: 3, ok: 1, total: 5 }
  },
  permissive: {
    cooldownMultiplier: 0.55,
    maxVisible: { critical: 3, warning: 4, ok: 2, total: 7 }
  }
};

const compareLiveAlertPriority = (left, right) => {
  const severityDelta =
    (LIVE_ALERT_SEVERITY_WEIGHT[right.severity] || 0) -
    (LIVE_ALERT_SEVERITY_WEIGHT[left.severity] || 0);
  if (severityDelta !== 0) return severityDelta;
  const rightTime = Date.parse(right.createdAt || '') || 0;
  const leftTime = Date.parse(left.createdAt || '') || 0;
  return rightTime - leftTime;
};

const capLiveAlertsBySeverity = (alerts, maxVisible) => {
  const capped = [];
  const counts = { critical: 0, warning: 0, ok: 0 };
  for (const item of alerts) {
    const severity = item.severity === 'critical' || item.severity === 'ok'
      ? item.severity
      : 'warning';
    const severityLimit = maxVisible[severity] ?? 1;
    if (counts[severity] >= severityLimit) {
      continue;
    }
    if (capped.length >= (maxVisible.total ?? 5)) {
      break;
    }
    counts[severity] += 1;
    capped.push({ ...item, severity });
  }
  return capped;
};

const extractSessionIdFromAuditItem = (item) => {
  if (!item?.payloadIsJson || !item?.payloadRaw) return null;
  try {
    const payload = JSON.parse(item.payloadRaw);
    const sessionId = Number(payload?.sessionId || 0);
    return Number.isFinite(sessionId) && sessionId > 0 ? sessionId : null;
  } catch (_) {
    return null;
  }
};

const DEFAULT_SSH_SNIPPETS = [
  { id: 'health', labelKey: 'Health Snapshot', command: 'whoami && hostname && uptime' },
  { id: 'net', labelKey: 'Network Quick Check', command: 'ip a && ss -tulpen | head -n 30' },
  { id: 'disk', labelKey: 'Disk Pressure', command: 'df -h && du -sh /var/log 2>/dev/null' },
  { id: 'proc', labelKey: 'Top Processes', command: 'ps aux --sort=-%cpu | head -n 15' }
];

const ACCESS_PLAYBOOK_STORAGE_KEY = 'endoriumfort_access_playbooks';

export default function App() {
  const { locale, t, raw } = useI18n();
  const [auth, setAuth] = useState(() => {
    try {
      const saved = localStorage.getItem('endoriumfort_auth');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed.token) {
          setAuthToken(parsed.token);
          return {
            user: parsed.user || '',
            password: '',
            role: normalizeRole(parsed.role),
            token: parsed.token,
            permissions: Array.isArray(parsed.permissions) ? parsed.permissions : []
          };
        }
      }
    } catch (_) {}
    return { user: '', password: '', role: 'operator', token: '', permissions: [] };
  });
  const [authError, setAuthError] = useState('');
  const [ssoLogin, setSsoLogin] = useState({ available: false });
  const [sessions, setSessions] = useState([]);
  const [loadingSessions, setLoadingSessions] = useState(true);
  const [sessionError, setSessionError] = useState('');
  const [activeTerminalSession, setActiveTerminalSession] = useState(null);
  const [terminalStatus, setTerminalStatus] = useState('idle');
  const [terminalError, setTerminalError] = useState('');
  const [terminalInfo, setTerminalInfo] = useState('');
  const [sshPassword, setSshPassword] = useState('');
  const [snippetLabel, setSnippetLabel] = useState('');
  const [snippetCommand, setSnippetCommand] = useState('');
  const [customSnippets, setCustomSnippets] = useState(() => {
    try {
      const raw = localStorage.getItem('endoriumfort_custom_ssh_snippets');
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
      return [];
    }
  });
  const [terminalReady, setTerminalReady] = useState(false);
  const [autoConnectSessionId, setAutoConnectSessionId] = useState(null);
  // A shell the server kept after a page reload: reattaching needs no password.
  const [resumeSessionId, setResumeSessionId] = useState(null);
  const [auditItems, setAuditItems] = useState([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [auditError, setAuditError] = useState('');
  const [auditFilter, setAuditFilter] = useState(null);
  // Session to show first on the evidence page (set when coming from Sessions or Journal).
  const [evidenceFocus, setEvidenceFocus] = useState(null);
  // User to filter the journal on when coming from Administration > Users.
  const [journalActorFocus, setJournalActorFocus] = useState(null);
  // Resource to open in Administration > Resources (from the map or zones).
  const [resourceEditFocus, setResourceEditFocus] = useState(null);
  const [resources, setResources] = useState([]);
  const [loadingResources, setLoadingResources] = useState(false);
  const [resourceError, setResourceError] = useState('');
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  // Access profiles are shared: JIT governance (@pro) does CRUD, and the Users
  // access-scope editor consumes the list to assign profiles to users.
  const [accessProfiles, setAccessProfiles] = useState([]);
  const [accessGrants, setAccessGrants] = useState([]);
  const [loadingAccessGrants, setLoadingAccessGrants] = useState(false);
  // Per-session routing hints (direct/relay) shown on session cards. Core display
  // fed by fetchRelayResolution; kept in the shell (the relay ADMIN panel is @pro).
  const [sessionRelayHints, setSessionRelayHints] = useState({});
  const [route, setRoute] = useState(() =>
    window.location.pathname ? window.location.pathname : '/'
  );
  const [adminSection, setAdminSection] = useState('resources');
  // Licensing / editions (open-core freemium gating)
  const [licenseStatus, setLicenseStatus] = useState(null);
  // Version reported by the server (GET /api/health), shown once signed in.
  const [bastionVersion, setBastionVersion] = useState('');
  // Appearance (Pro): tab title/icon and login background, public and loaded before sign-in.
  const [branding, setBranding] = useState(null);
  const [licenseUpsell, setLicenseUpsell] = useState(null); // {feature, requiredTier} | null
  const [licenseBannerDismissed, setLicenseBannerDismissed] = useState(false);
  const [licenseUploadText, setLicenseUploadText] = useState('');
  const [licenseBusy, setLicenseBusy] = useState(false);
  const [licenseActionMsg, setLicenseActionMsg] = useState(null); // {error, message} | null
  const [vncViewerSession, setVncViewerSession] = useState(null);
  const [rbiViewerSession, setRbiViewerSession] = useState(null);
  const [accessPromptResource, setAccessPromptResource] = useState(null);
  const [accessPromptReason, setAccessPromptReason] = useState('');
  const [accessPromptTicketId, setAccessPromptTicketId] = useState('');
  const [accessPromptPurpose, setAccessPromptPurpose] = useState('');
  const [accessPromptPurposeEvidence, setAccessPromptPurposeEvidence] = useState('');
  const [accessPromptMode, setAccessPromptMode] = useState('connect');
  // Approved access request the dialog will attach to the session it opens.
  const [accessPromptRequestId, setAccessPromptRequestId] = useState(null);
  const [accessPlaybooks, setAccessPlaybooks] = useState(() => {
    try {
      const raw = localStorage.getItem(ACCESS_PLAYBOOK_STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
      return [];
    }
  });
  const [riskPreview, setRiskPreview] = useState(null);
  const [riskPreviewLoading, setRiskPreviewLoading] = useState(false);
  const [riskPreviewError, setRiskPreviewError] = useState('');
  const [accessRequests, setAccessRequests] = useState([]);
  const [loadingAccessRequests, setLoadingAccessRequests] = useState(false);
  const [accessRequestError, setAccessRequestError] = useState('');
  // 2FA state
  const [twoFARequired, setTwoFARequired] = useState(false);
  const [availableMfaMethods, setAvailableMfaMethods] = useState([]);
  const [totpCode, setTotpCode] = useState('');
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [totpSetupData, setTotpSetupData] = useState(null);
  const [totpSetupCode, setTotpSetupCode] = useState('');
  const [totpError, setTotpError] = useState('');
  const [totpDisableCode, setTotpDisableCode] = useState('');
  const [totpQrDataUrl, setTotpQrDataUrl] = useState('');
  const [webauthnEnabled, setWebauthnEnabled] = useState(false);
  const [webauthnCredentials, setWebauthnCredentials] = useState([]);
  const [webauthnLoginOptions, setWebauthnLoginOptions] = useState(null);
  const [webauthnBusy, setWebauthnBusy] = useState(false);
  const [webauthnLabel, setWebauthnLabel] = useState('');
  const [preferredMfaMethod, setPreferredMfaMethod] = useState('any');
  // Dashboard stats
  const [stats, setStats] = useState(null);
  const [securityAuditItems, setSecurityAuditItems] = useState([]);
  const [liveSecurityAlerts, setLiveSecurityAlerts] = useState([]);
  const [liveSecurityIncident, setLiveSecurityIncident] = useState(null);
  const [containmentStatus, setContainmentStatus] = useState({
    enabled: false,
    updatedAt: '',
    updatedBy: '',
    reason: ''
  });
  const [activeSecurityIncident, setActiveSecurityIncident] = useState({
    active: false,
    incident: null
  });
  const [incidentCaseBusy, setIncidentCaseBusy] = useState(false);
  const [containmentBusy, setContainmentBusy] = useState(false);
  const [incidentTerminateConfirmOpen, setIncidentTerminateConfirmOpen] = useState(false);
  const [incidentTerminateBusy, setIncidentTerminateBusy] = useState(false);
  const [liveAlertProfile, setLiveAlertProfile] = useState(() => {
    try {
      const saved = localStorage.getItem('endoriumfort_live_alert_profile');
      return saved && LIVE_ALERT_PROFILES[saved] ? saved : 'normal';
    } catch (_) {
      return 'normal';
    }
  });
  // Shadow session (admin live monitoring)
  const [shadowSession, setShadowSession] = useState(null);
  const [shadowStatus, setShadowStatus] = useState('idle');
  const shadowTermRef = useRef(null);
  const shadowTermInstanceRef = useRef(null);
  const shadowFitRef = useRef(null);
  const shadowSocketRef = useRef(null);
  // Agent launch modal
  const [agentModal, setAgentModal] = useState(null); // { resource, port, command, copied }
  const agentLaunchTimeoutRef = useRef(null);
  const agentLaunchCleanupRef = useRef(null);
  // Dark mode
  const [darkMode, setDarkMode] = useState(() => {
    try { return localStorage.getItem('endoriumfort_darkmode') === 'true'; } catch (_) { return false; }
  });
  // Change password
  const [changePwCurrent, setChangePwCurrent] = useState('');
  const [changePwNew, setChangePwNew] = useState('');
  const [changePwConfirm, setChangePwConfirm] = useState('');
  const [changePwError, setChangePwError] = useState('');
  const [changePwSuccess, setChangePwSuccess] = useState('');
  const [bootstrapState, setBootstrapState] = useState({
    required: false,
    passwordChangeRequired: false,
    mfaSetupRequired: false,
    totpEnabled: false,
    webauthnEnabled: false
  });
  // Token expiry
  const [tokenExpiresAt, setTokenExpiresAt] = useState('');
  const terminalRef = useRef(null);
  // Long-lived xterm host: pages move this node around instead of owning it, so
  // an open SSH terminal survives switching sections.
  if (!terminalRef.current && typeof document !== 'undefined') {
    const host = document.createElement('div');
    host.className = 'ef-term__host';
    terminalRef.current = host;
  }
  const terminalInstanceRef = useRef(null);
  const fitAddonRef = useRef(null);
  const socketRef = useRef(null);
  const terminalInputListenerRef = useRef(null);
  const securityFeedBootstrappedRef = useRef(false);
  const lastSecurityAuditIdRef = useRef(0);
  const liveAlertCooldownByTypeRef = useRef({});
  const liveIncidentCriticalTimestampsRef = useRef([]);
  const liveIncidentCooldownUntilRef = useRef(0);

  // ── Licensing / editions ────────────────────────────────────────────────
  const licenseEdition = licenseStatus?.edition || 'community';
  const licenseState = licenseStatus?.state || 'none';
  const licenseValid = licenseState === 'valid';
  const activeTier = licenseValid ? (licenseStatus?.tier || 'free') : 'free';
  const TIER_RANK = { free: 0, pro: 1, enterprise: 2 };
  // A premium capability is available only in the Enterprise edition (the CE build
  // physically lacks the routes) AND when the loaded license reaches its tier.
  const premiumUnlocked = (requiredTier) =>
    licenseEdition === 'enterprise' &&
    (TIER_RANK[activeTier] || 0) >= (TIER_RANK[requiredTier] || 0);
  const openUpsell = (feature, requiredTier) =>
    setLicenseUpsell({ feature: feature || '', requiredTier: requiredTier || 'pro' });
  const licenseDaysRemaining = Number(licenseStatus?.daysRemaining);
  // Only poll premium endpoints when the license actually grants them. Otherwise
  // background pollers 403 on landing → spurious upsell popups + console noise.
  const securityCenterLicensed = premiumUnlocked('enterprise');
  const jitLicensed = premiumUnlocked('pro');
  const relaysLicensed = premiumUnlocked('pro');

  const canManagePlatform = hasCapability(auth.role, auth.permissions, 'manageResources');
  const canViewAudit = hasCapability(auth.role, auth.permissions, 'viewAudit');
  const canViewRecordings = hasCapability(auth.role, auth.permissions, 'viewRecordings');
  const canOperateSessions = hasCapability(auth.role, auth.permissions, 'operateSessions');
  const roleName = roleLabel(auth.role, t);
  const visibleShellTabs = [
    'carte',
    'sessions',
    (canManagePlatform || jitLicensed) && 'demandes',
    canViewAudit && 'journal',
    canViewRecordings && 'preuves',
    canManagePlatform && 'zones',
    canManagePlatform && 'admin'
  ].filter(Boolean);
  const activeLiveAlertProfile = LIVE_ALERT_PROFILES[liveAlertProfile] || LIVE_ALERT_PROFILES.normal;
  const containmentEnabled = !!containmentStatus.enabled;
  const bootstrapRequired = !!(auth.token && bootstrapState.required);
  const roleBlueprints = useMemo(() => ([
    {
      id: 'operator',
      label: t('roles.operator.label'),
      description: t('roles.operator.description'),
      permissions: raw('roles.operator.permissions') || []
    },
    {
      id: 'admin',
      label: t('roles.admin.label'),
      description: t('roles.admin.description'),
      permissions: raw('roles.admin.permissions') || []
    },
    {
      id: 'auditor',
      label: t('roles.auditor.label'),
      description: t('roles.auditor.description'),
      permissions: raw('roles.auditor.permissions') || []
    }
  ]), [raw, t]);

  useEffect(() => {
    try {
      localStorage.setItem('endoriumfort_live_alert_profile', liveAlertProfile);
    } catch (_) {}
  }, [liveAlertProfile]);

  useEffect(() => {
    try {
      localStorage.setItem('endoriumfort_custom_ssh_snippets', JSON.stringify(customSnippets));
    } catch (_) {}
  }, [customSnippets]);

  useEffect(() => {
    try {
      localStorage.setItem(ACCESS_PLAYBOOK_STORAGE_KEY, JSON.stringify(accessPlaybooks));
    } catch (_) {}
  }, [accessPlaybooks]);

  const currentAccessPlaybook = useMemo(() => {
    const resourceId = Number(accessPromptResource?.id) || 0;
    if (!resourceId) return null;
    return (
      accessPlaybooks.find((item) => Number(item.resourceId) === resourceId) || null
    );
  }, [accessPlaybooks, accessPromptResource]);

  const sshSnippetLibrary = useMemo(() => {
    const normalizedCustom = customSnippets
      .map((item) => ({
        id: String(item.id || ''),
        label: String(item.label || '').trim(),
        command: String(item.command || '').trim()
      }))
      .filter((item) => item.id && item.label && item.command)
      .map((item) => ({ ...item, custom: true }));
    return [
      ...DEFAULT_SSH_SNIPPETS.map((item) => ({ ...item, label: item.labelKey, custom: false })),
      ...normalizedCustom
    ];
  }, [customSnippets]);


  const adminSections = useMemo(() => {
    const adminsWithoutMfa = stats?.users?.adminsWithoutMfa || 0;
    const pendingRequests = accessRequests.filter((item) => item.status === 'pending').length;
    // Premium sections are locked unless the Enterprise edition + license entitle them.
    const lockOf = (requiredTier) =>
      !(licenseEdition === 'enterprise' &&
        (TIER_RANK[activeTier] || 0) >= (TIER_RANK[requiredTier] || 0));
    return [
      {
        id: 'resources',
        label: t('admin.resources'),
        hint: t('admin.inventoryAndPolicies'),
        badge: String(resources.length),
        badgeTone: loadingResources ? 'loading' : 'ok'
      },
      {
        id: 'users',
        label: t('admin.users'),
        hint: t('admin.accountsAndAccessScope'),
        badge: String(users.length),
        badgeTone: loadingUsers ? 'loading' : 'ok'
      },
      {
        id: 'routing',
        label: t('admin.routing'),
        hint: t('admin.relaysAndApprovals'),
        requiredTier: 'pro',
        locked: lockOf('pro'),
        badge: lockOf('pro') ? '🔒' : (pendingRequests ? t('admin.pendingCount', { count: pendingRequests }) : t('admin.healthy')),
        badgeTone: lockOf('pro') ? 'locked' : (pendingRequests ? 'active' : 'ok')
      },
      {
        id: 'jit',
        label: 'JIT',
        hint: 'Policies, profiles and grants',
        requiredTier: 'pro',
        locked: lockOf('pro'),
        badge: lockOf('pro') ? '🔒' : String(accessGrants.length),
        badgeTone: lockOf('pro') ? 'locked' : (loadingAccessGrants ? 'loading' : 'ok')
      },
      {
        id: 'enterprise',
        label: 'Enterprise IAM',
        hint: 'LDAP/AD, SSO, SCIM, ITSM, SIEM',
        requiredTier: 'enterprise',
        locked: lockOf('enterprise'),
        badge: lockOf('enterprise') ? '🔒' : 'SSO·LDAP·SCIM',
        badgeTone: lockOf('enterprise') ? 'locked' : 'ok'
      },
      {
        id: 'vault',
        label: locale === 'fr' ? 'Coffre-fort' : 'Vault',
        hint: locale === 'fr' ? 'Rotation + secrets dynamiques' : 'Rotation + dynamic secrets',
        requiredTier: 'enterprise',
        locked: lockOf('enterprise'),
        badge: lockOf('enterprise') ? '🔒' : (locale === 'fr' ? 'Rotation·Éphémère' : 'Rotation·Ephemeral'),
        badgeTone: lockOf('enterprise') ? 'locked' : 'ok'
      },
      {
        id: 'itdr',
        label: 'ITDR',
        hint: locale === 'fr' ? 'Détection menaces + réponse' : 'Threat detection + response',
        requiredTier: 'enterprise',
        locked: lockOf('enterprise'),
        badge: lockOf('enterprise') ? '🔒' : (locale === 'fr' ? 'Détection·Réponse' : 'Detect·Respond'),
        badgeTone: lockOf('enterprise') ? 'locked' : 'ok'
      },
      {
        id: 'k8s',
        label: 'Kubernetes',
        hint: locale === 'fr' ? 'Exec shell dans les pods' : 'Pod exec shell',
        requiredTier: 'pro',
        locked: lockOf('pro'),
        badge: lockOf('pro') ? '🔒' : 'kubectl exec',
        badgeTone: lockOf('pro') ? 'locked' : 'ok'
      },
      {
        id: 'appearance',
        label: t('adminE.nav.appearance'),
        hint: t('appearance.hint'),
        requiredTier: 'pro',
        locked: lockOf('pro'),
        badge: lockOf('pro') ? '🔒' : '',
        badgeTone: lockOf('pro') ? 'locked' : 'ok'
      },
      {
        id: 'security',
        label: t('admin.security'),
        hint: t('admin.mfaAndPosture'),
        // Core section: own-MFA management (TOTP/passkeys) + security posture from
        // /api/stats. The premium "Security Center" (live incidents/containment via
        // /api/security/*) is the app-wide banner/toasts, not this admin tab.
        badge: adminsWithoutMfa ? t('admin.riskCount', { count: adminsWithoutMfa }) : t('admin.healthy'),
        badgeTone: adminsWithoutMfa ? 'loading' : 'ok'
      },
      {
        // Core section: view/upload the offline license (governs premium in EE).
        id: 'license',
        label: locale === 'fr' ? 'Licence' : 'License',
        hint: locale === 'fr' ? 'Statut, expiration, upload' : 'Status, expiry, upload',
        badge: (licenseStatus?.tier && licenseStatus?.state === 'valid')
          ? String(licenseStatus.tier)
          : (licenseStatus?.state || 'none'),
        badgeTone: licenseStatus?.state === 'valid'
          ? 'ok'
          : (licenseStatus?.state === 'expired' || licenseStatus?.state === 'revoked' ? 'locked' : 'loading')
      }
    ];
  }, [accessGrants.length, accessRequests, activeTier, licenseEdition, licenseStatus, loadingAccessGrants, loadingResources, loadingUsers, locale, resources.length, stats?.users?.adminsWithoutMfa, t, users.length]);

  // Order and wording of the redesigned Administration menu.
  const adminNavSections = useMemo(() => {
    const order = ['resources', 'users', 'jit', 'routing', 'vault', 'security', 'itdr', 'enterprise', 'k8s', 'appearance', 'license'];
    const adminsWithoutMfa = stats?.users?.adminsWithoutMfa || 0;
    return order
      .map((id) => adminSections.find((section) => section.id === id))
      .filter(Boolean)
      .map((section) => ({
        id: section.id,
        label: t(`adminE.nav.${section.id}`),
        locked: !!section.locked,
        count: section.id === 'resources' ? resources.length : section.id === 'users' ? users.length : null,
        alert: section.id === 'security' && adminsWithoutMfa ? String(adminsWithoutMfa) : null
      }));
  }, [adminSections, resources.length, users.length, stats?.users?.adminsWithoutMfa, t]);


  const navigate = (path) => {
    if (window.location.pathname !== path) {
      window.history.pushState({}, '', path);
      setRoute(path);
    }
  };

  useEffect(() => {
    const handlePopState = () => {
      setRoute(window.location.pathname || '/');
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  useEffect(() => {
    const onUnauthorized = () => {
      setAuth((prev) => ({ ...prev, token: '', password: '', permissions: [] }));
      setAuthError(t('auth.sessionExpired'));
      setTokenExpiresAt('');
      setBootstrapState({
        required: false,
        passwordChangeRequired: false,
        mfaSetupRequired: false,
        totpEnabled: false,
        webauthnEnabled: false
      });
      setWebauthnEnabled(false);
      setWebauthnCredentials([]);
      setWebauthnLoginOptions(null);
      setAvailableMfaMethods([]);
      setPreferredMfaMethod('any');
      setAuthToken('');
      navigate('/login');
    };
    window.addEventListener('endoriumfort:unauthorized', onUnauthorized);
    return () => window.removeEventListener('endoriumfort:unauthorized', onUnauthorized);
  }, [t]);

  // License status: load once authenticated; refresh the banner/gating state.
  useEffect(() => {
    if (!auth.token) {
      setLicenseStatus(null);
      return;
    }
    let active = true;
    fetchLicenseStatus()
      .then((status) => { if (active) setLicenseStatus(status); })
      .catch(() => { if (active) setLicenseStatus(null); });
    return () => { active = false; };
  }, [auth.token]);

  useEffect(() => {
    if (!auth.token) return undefined;
    let active = true;
    fetchHealth()
      .then((health) => { if (active) setBastionVersion(String(health?.version || '')); })
      .catch(() => {});
    return () => { active = false; };
  }, [auth.token]);

  useEffect(() => {
    let active = true;
    fetchBranding()
      .then((value) => { if (active) setBranding(value); })
      .catch(() => {});
    return () => { active = false; };
  }, [auth.token]);

  useEffect(() => { applyBranding(branding); }, [branding]);

  // Login page: offer SSO only when the backend has a configured provider.
  useEffect(() => {
    if (auth.token) return undefined;
    let active = true;
    fetchSsoLoginOptions().then((options) => { if (active) setSsoLogin(options); });
    return () => { active = false; };
  }, [auth.token]);

  // Premium routes reply 403 + license-required header → open the upsell modal.
  useEffect(() => {
    const onLicenseRequired = (event) => {
      const detail = event?.detail || {};
      setLicenseUpsell({
        feature: detail.feature || '',
        requiredTier: detail.requiredTier || 'pro'
      });
    };
    window.addEventListener('endoriumfort:license-required', onLicenseRequired);
    return () => window.removeEventListener('endoriumfort:license-required', onLicenseRequired);
  }, []);

  // Dark mode effect
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', darkMode ? 'dark' : 'light');
    localStorage.setItem('endoriumfort_darkmode', darkMode ? 'true' : 'false');
  }, [darkMode]);

  useEffect(() => {
    const onKeyDown = (event) => {
      // Alt+1…7 jumps to the visible top-level tabs, in display order.
      if (event.altKey && !event.metaKey && !event.ctrlKey) {
        const index = Number(event.key) - 1;
        const tabs = SHELL_TABS.filter((tab) => visibleShellTabs.includes(tab.id));
        if (Number.isInteger(index) && tabs[index]) {
          event.preventDefault();
          navigate(tabs[index].path);
        }
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [visibleShellTabs.join(',')]);

  // /admin/<section> selects that Administration section.
  useEffect(() => {
    const match = /^\/admin\/([a-z0-9]+)/.exec(route);
    if (match && adminSections.some((section) => section.id === match[1] && !section.locked)) setAdminSection(match[1]);
    // Re-run once the license is known: premium sections look locked until then.
  }, [route, licenseEdition, activeTier]);

  // The map shows today's journal, the sessions page each session's events, and the
  // journal page the full log.
  useEffect(() => {
    const tab = tabForPath(route)?.id;
    if (!auth.token) return;
    if (tab === 'journal' || (['carte', 'sessions'].includes(tab) && canViewAudit)) loadAudit();
  }, [route, auth.token, canViewAudit]);

  // Token expiry auto-logout
  useEffect(() => {
    if (!tokenExpiresAt || !auth.token) return;
    const remaining = new Date(tokenExpiresAt).getTime() - Date.now();
    if (remaining <= 0) {
      onLogout();
      return;
    }
    const timer = setTimeout(() => {
      onLogout();
      setAuthError(t('auth.sessionExpired'));
    }, remaining);
    return () => clearTimeout(timer);
  }, [tokenExpiresAt, auth.token, t]);

  useEffect(() => {
    if (!auth.token && route !== '/login') {
      navigate('/login');
    }
    if (auth.token && route === '/login') {
      navigate('/');
    }
  }, [auth.token, route]);

  useEffect(() => {
    if (!auth.token) {
      setSessions([]);
      setLoadingSessions(false);
      return;
    }
    let active = true;
    setLoadingSessions(true);
    fetchSessions()
      .then((data) => {
        if (!active) return;
        setSessions(Array.isArray(data.items) ? data.items : []);
        setSessionError('');
      })
      .catch((error) => {
        if (!active) return;
        setSessionError(error.message || 'Unable to load sessions');
      })
      .finally(() => {
        if (!active) return;
        setLoadingSessions(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token]);

  useEffect(() => {
    if (!auth.token) {
      setResources([]);
      setLoadingResources(false);
      return;
    }
    let active = true;
    setLoadingResources(true);
    fetchResources()
      .then((data) => {
        if (!active) return;
        setResources(Array.isArray(data.items) ? data.items : []);
        setResourceError('');
      })
      .catch((error) => {
        if (!active) return;
        setResourceError(error.message || 'Unable to load resources');
      })
      .finally(() => {
        if (!active) return;
        setLoadingResources(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token]);

  useEffect(() => {
    if (!auth.token || !jitLicensed) {
      setAccessRequests([]);
      setLoadingAccessRequests(false);
      return;
    }
    let active = true;
    setLoadingAccessRequests(true);
    fetchAccessRequests()
      .then((data) => {
        if (!active) return;
        setAccessRequests(Array.isArray(data.items) ? data.items : []);
        setAccessRequestError('');
      })
      .catch((error) => {
        if (!active) return;
        setAccessRequestError(error.message || 'Unable to load access requests');
      })
      .finally(() => {
        if (!active) return;
        setLoadingAccessRequests(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token, jitLicensed]);

  useEffect(() => {
    if (!auth.token || !canManagePlatform) {
      setUsers([]);
      setLoadingUsers(false);
      return;
    }
    let active = true;
    setLoadingUsers(true);
    fetchUsers()
      .then((data) => {
        if (!active) return;
        setUsers(Array.isArray(data.items) ? data.items : []);
      })
      .catch(() => {})
      .finally(() => {
        if (!active) return;
        setLoadingUsers(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token, canManagePlatform]);


  // Shared access-profile list loader (used by JIT @pro CRUD + Users editor).
  useEffect(() => {
    if (!auth.token || !canManagePlatform || !jitLicensed) {
      setAccessProfiles([]);
      return;
    }
    let active = true;
    fetchAccessProfiles()
      .then((data) => {
        if (!active) return;
        setAccessProfiles(Array.isArray(data.items) ? data.items : []);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [auth.token, canManagePlatform, jitLicensed]);

  useEffect(() => {
    if (!auth.token || !jitLicensed) {
      setAccessGrants([]);
      setLoadingAccessGrants(false);
      return;
    }
    let active = true;
    setLoadingAccessGrants(true);
    fetchAccessGrants()
      .then((data) => {
        if (!active) return;
        setAccessGrants(Array.isArray(data.items) ? data.items : []);
      })
      .catch(() => {})
      .finally(() => {
        if (!active) return;
        setLoadingAccessGrants(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token, jitLicensed]);


  // Fetch dashboard stats periodically
  useEffect(() => {
    if (!auth.token) { setStats(null); return; }
    let active = true;
    const load = () => {
      fetchStats()
        .then((data) => { if (active) setStats(data); })
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, 15000); // refresh every 15s
    return () => { active = false; clearInterval(interval); };
  }, [auth.token]);

  // Coming back to the map: refresh now, so the getting-started steps reflect
  // what was just done elsewhere (e.g. two-factor sign-in turned on), and
  // again once the first-login two-factor setup is finished.
  const mfaSetupPending = !!bootstrapState?.mfaSetupRequired;
  const onMapTab = !route.startsWith('/compte') && (tabForPath(route)?.id || 'carte') === 'carte';
  useEffect(() => {
    if (!auth.token || !onMapTab || !canManagePlatform) return undefined;
    let active = true;
    fetchStats()
      .then((data) => { if (active) setStats(data); })
      .catch(() => {});
    return () => { active = false; };
  }, [auth.token, onMapTab, canManagePlatform, mfaSetupPending]);

  useEffect(() => {
    if (!auth.token || !canViewAudit) {
      setSecurityAuditItems([]);
      setLiveSecurityAlerts([]);
      setLiveSecurityIncident(null);
      setContainmentStatus({ enabled: false, updatedAt: '', updatedBy: '', reason: '' });
      setActiveSecurityIncident({ active: false, incident: null });
      securityFeedBootstrappedRef.current = false;
      lastSecurityAuditIdRef.current = 0;
      liveAlertCooldownByTypeRef.current = {};
      liveIncidentCriticalTimestampsRef.current = [];
      liveIncidentCooldownUntilRef.current = 0;
      return;
    }
    let active = true;
    const load = () => {
      fetchAudit()
        .then((data) => {
          if (!active) return;
          setSecurityAuditItems(Array.isArray(data.items) ? data.items : []);
        })
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, 20000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [auth.token, canViewAudit]);

  useEffect(() => {
    if (!auth.token || !canViewAudit || !securityCenterLicensed) {
      setContainmentStatus({ enabled: false, updatedAt: '', updatedBy: '', reason: '' });
      return;
    }
    let active = true;
    const load = () => {
      fetchContainmentStatus()
        .then((data) => {
          if (!active) return;
          setContainmentStatus({
            enabled: !!data?.enabled,
            updatedAt: data?.updatedAt || '',
            updatedBy: data?.updatedBy || '',
            reason: data?.reason || ''
          });
        })
        .catch(() => {
          if (!active) return;
          setContainmentStatus({ enabled: false, updatedAt: '', updatedBy: '', reason: '' });
        });
    };
    load();
    const interval = window.setInterval(load, 15000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [auth.token, canViewAudit, securityCenterLicensed]);

  useEffect(() => {
    if (!auth.token || !canViewAudit || !securityCenterLicensed) {
      setActiveSecurityIncident({ active: false, incident: null });
      return;
    }
    let active = true;
    const load = () => {
      fetchActiveSecurityIncident()
        .then((data) => {
          if (!active) return;
          setActiveSecurityIncident({
            active: !!data?.active,
            incident: data?.incident || null
          });
        })
        .catch(() => {
          if (!active) return;
          setActiveSecurityIncident({ active: false, incident: null });
        });
    };
    load();
    const interval = window.setInterval(load, 15000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [auth.token, canViewAudit, securityCenterLicensed]);

  useEffect(() => {
    if (!auth.token || !canViewAudit || !securityCenterLicensed) {
      return undefined;
    }

    let active = true;
    const load = async () => {
      try {
        const sinceId = lastSecurityAuditIdRef.current;
        const data = await fetchSecurityAlerts(sinceId);
        if (!active) return;

        const nextMaxId = Number(data?.maxEventId) || sinceId;
        const items = Array.isArray(data?.items) ? data.items : [];

        if (!securityFeedBootstrappedRef.current) {
          securityFeedBootstrappedRef.current = true;
          lastSecurityAuditIdRef.current = Math.max(sinceId, nextMaxId);
          return;
        }

        if (items.length) {
          const nowMs = Date.now();
          const incidentWindowMs = 5 * 60 * 1000;
          const incidentThreshold = 3;
          const nextCriticalTimestamps = [
            ...liveIncidentCriticalTimestampsRef.current.filter((ts) => ts >= nowMs - incidentWindowMs),
            ...items
              .filter((item) => String(item.severity || '').toLowerCase() === 'critical')
              .map((item) => Date.parse(item.createdAt || '') || nowMs)
          ];
          liveIncidentCriticalTimestampsRef.current = nextCriticalTimestamps;

          if (
            nextCriticalTimestamps.length >= incidentThreshold &&
            nowMs >= liveIncidentCooldownUntilRef.current
          ) {
            liveIncidentCooldownUntilRef.current = nowMs + incidentWindowMs;
            setLiveSecurityIncident({
              key: `incident:${nowMs}`,
              createdAt: new Date(nowMs).toISOString(),
              criticalCount: nextCriticalTimestamps.length,
              title: 'Potential Security Incident',
              hint: 'Multiple critical signals observed in a short window. Escalate and investigate immediately.'
            });
            reportSecurityIncidentEscalation({
              criticalCount: nextCriticalTimestamps.length,
              windowSeconds: Math.floor(incidentWindowMs / 1000),
              profile: liveAlertProfile
            }).catch(() => {
              // Keep incident UX independent from audit reporting failures.
            });

            if (!activeSecurityIncident?.active) {
              openSecurityIncident({
                criticalCount: nextCriticalTimestamps.length,
                windowSeconds: Math.floor(incidentWindowMs / 1000),
                profile: liveAlertProfile,
                title: 'Potential Security Incident',
                summary: 'Automatically opened from repeated critical live security signals.'
              })
                .then((opened) => {
                  setActiveSecurityIncident({
                    active: !!opened?.active,
                    incident: opened?.incident || null
                  });
                })
                .catch(() => {
                  // Keep signal-to-incident UI non-blocking.
                });
            }
          }

          setLiveSecurityAlerts((prev) => {
            const existing = new Set(prev.map((item) => item.key));
            const throttledBySeverity = { critical: 0, warning: 0, ok: 0 };
            const incoming = items
              .map((item) => ({
                key: `${item.id}:${item.eventType}`,
                eventType: item.eventType,
                sessionId: Number(item.sessionId) || null,
                createdAt: item.createdAt,
                severity: item.severity || 'warning',
                title: item.title || 'Security Signal',
                hint: item.hint || 'Investigate in audit timeline.'
              }))
              .sort(compareLiveAlertPriority)
              .filter((item) => {
                if (existing.has(item.key)) return false;
                const baseCooldown = LIVE_ALERT_COOLDOWN_MS[item.severity] ?? 60000;
                const cooldownMs = Math.round(
                  baseCooldown * (activeLiveAlertProfile.cooldownMultiplier || 1)
                );
                const cooldownKey = item.eventType || item.severity;
                const lastShownAt = liveAlertCooldownByTypeRef.current[cooldownKey] || 0;
                if (nowMs - lastShownAt < cooldownMs) {
                  throttledBySeverity[item.severity] =
                    (throttledBySeverity[item.severity] || 0) + 1;
                  return false;
                }
                liveAlertCooldownByTypeRef.current[cooldownKey] = nowMs;
                return true;
              });

            const suppressedCount = Object.values(throttledBySeverity).reduce(
              (sum, count) => sum + count,
              0
            );
            if (suppressedCount > 0) {
              incoming.push({
                key: `throttled:${nowMs}`,
                eventType: 'security.alerts.throttled',
                createdAt: new Date(nowMs).toISOString(),
                severity:
                  throttledBySeverity.warning > 0 || throttledBySeverity.critical > 0
                    ? 'warning'
                    : 'ok',
                count: suppressedCount,
                title: `${suppressedCount} signal${suppressedCount > 1 ? 's' : ''} grouped`,
                hint: 'Low-priority duplicates were throttled to keep focus on high-risk events.'
              });
            }

            const merged = [...incoming, ...prev].sort(compareLiveAlertPriority);
            return capLiveAlertsBySeverity(merged, activeLiveAlertProfile.maxVisible);
          });
        }

        lastSecurityAuditIdRef.current = Math.max(sinceId, nextMaxId);
      } catch (_) {
        // Keep security feed non-blocking for the rest of the UI.
      }
    };

    load();
    const interval = window.setInterval(load, 10000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [auth.token, canViewAudit, activeLiveAlertProfile, activeSecurityIncident, securityCenterLicensed]);

  useEffect(() => {
    if (!liveSecurityAlerts.length) {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      setLiveSecurityAlerts((prev) => prev.slice(0, -1));
    }, 9000);
    return () => window.clearTimeout(timer);
  }, [liveSecurityAlerts]);

  const dismissLiveSecurityAlert = (alertKey) => {
    setLiveSecurityAlerts((prev) => prev.filter((item) => item.key !== alertKey));
  };

  const dismissLiveSecurityIncident = () => {
    setLiveSecurityIncident(null);
  };

  const incidentSuspectSessions = useMemo(() => {
    if (!liveSecurityIncident) return [];
    const incidentTs = Date.parse(liveSecurityIncident.createdAt || '') || Date.now();
    const since = incidentTs - 5 * 60 * 1000;
    const bySessionId = new Map();

    const touchSuspicion = (sessionId, severity, createdAt) => {
      if (!sessionId || sessionId <= 0) return;
      const existing = bySessionId.get(sessionId) || {
        sessionId,
        signals: 0,
        criticalSignals: 0,
        lastSignalAt: 0
      };
      const signalTs = Date.parse(createdAt || '') || incidentTs;
      existing.signals += 1;
      if (String(severity || '').toLowerCase() === 'critical') {
        existing.criticalSignals += 1;
      }
      existing.lastSignalAt = Math.max(existing.lastSignalAt, signalTs);
      bySessionId.set(sessionId, existing);
    };

    securityAuditItems.forEach((item) => {
      const created = Date.parse(item?.createdAt || '') || 0;
      if (created < since) return;
      const type = String(item?.type || '').toLowerCase();
      const isSuspicious =
        type.includes('behavior.anomaly') ||
        type.includes('session.create.unjustified') ||
        (type.includes('session.dna') && type.includes('mismatch'));
      if (!isSuspicious) return;
      const sid = extractSessionIdFromAuditItem(item);
      const severity = type.includes('mismatch') ? 'critical' : 'warning';
      touchSuspicion(sid, severity, item?.createdAt);
    });

    liveSecurityAlerts.forEach((item) => {
      const created = Date.parse(item?.createdAt || '') || 0;
      if (created < since) return;
      const sid = Number(item?.sessionId) || 0;
      touchSuspicion(sid, item?.severity, item?.createdAt);
    });

    return Array.from(bySessionId.values())
      .map((entry) => {
        const matched = sessions.find((session) => session.id === entry.sessionId) || {
          id: entry.sessionId,
          status: 'unknown',
          target: 'n/a',
          user: 'n/a'
        };
        const minutesSince = Math.max(0, Math.floor((incidentTs - entry.lastSignalAt) / 60000));
        const recencyBonus = Math.max(0, 20 - minutesSince * 4);
        const activeBonus = matched.status === 'active' ? 30 : 0;
        const score =
          entry.signals * 20 +
          entry.criticalSignals * 25 +
          activeBonus +
          recencyBonus;
        return {
          ...matched,
          score,
          signals: entry.signals,
          criticalSignals: entry.criticalSignals,
          lastSignalAt: entry.lastSignalAt
        };
      })
      .sort((a, b) => b.score - a.score)
      .slice(0, 4);
  }, [liveSecurityIncident, securityAuditItems, liveSecurityAlerts, sessions]);

  const activeIncidentSuspectSessions = useMemo(
    () => incidentSuspectSessions.filter((session) => session.status === 'active'),
    [incidentSuspectSessions]
  );

  const requestTerminateIncidentSuspects = () => {
    if (!canOperateSessions) {
      setSessionError('You are not allowed to terminate sessions.');
      return;
    }
    if (!activeIncidentSuspectSessions.length) {
      setSessionError('No active correlated suspect sessions to terminate.');
      return;
    }
    setIncidentTerminateConfirmOpen(true);
  };

  const confirmTerminateIncidentSuspects = async () => {
    if (!activeIncidentSuspectSessions.length || incidentTerminateBusy) {
      return;
    }
    setIncidentTerminateBusy(true);
    try {
      const ids = activeIncidentSuspectSessions.map((session) => session.id);
      const results = await Promise.allSettled(ids.map((id) => terminateSession(id)));
      const updatedById = new Map();
      let failed = 0;
      results.forEach((result, index) => {
        if (result.status === 'fulfilled' && result.value) {
          updatedById.set(ids[index], result.value);
        } else {
          failed += 1;
        }
      });

      if (updatedById.size > 0) {
        setSessions((prev) =>
          prev.map((item) => updatedById.get(item.id) || item)
        );
      }

      if (failed > 0) {
        setSessionError(`${failed} suspect session(s) could not be terminated.`);
      } else {
        setSessionError('');
      }
    } catch (error) {
      setSessionError(error.message || 'Unable to terminate correlated suspect sessions');
    } finally {
      setIncidentTerminateBusy(false);
      setIncidentTerminateConfirmOpen(false);
    }
  };

  const setContainmentEnabled = async (enabled, reason) => {
    if (containmentBusy) return;
    if (!canManagePlatform) {
      setSessionError('Only platform admins can change containment mode.');
      return;
    }
    setContainmentBusy(true);
    try {
      const payload = await setContainmentMode({
        enabled,
        reason: reason || liveSecurityIncident?.title || 'incident.escalation'
      });
      setContainmentStatus({
        enabled: !!payload?.enabled,
        updatedAt: payload?.updatedAt || '',
        updatedBy: payload?.updatedBy || auth.user,
        reason: payload?.reason || ''
      });
      setSessionError('');
    } catch (error) {
      setSessionError(error.message || 'Unable to update containment mode');
    } finally {
      setContainmentBusy(false);
    }
  };

  const openIncidentCase = async () => {
    if (incidentCaseBusy) return;
    setIncidentCaseBusy(true);
    try {
      const payload = await openSecurityIncident({
        criticalCount: Number(liveSecurityIncident?.criticalCount || 0),
        windowSeconds: 300,
        profile: liveAlertProfile,
        title: liveSecurityIncident?.title || 'Potential Security Incident',
        summary: liveSecurityIncident?.hint || 'Opened manually from incident banner.'
      });
      setActiveSecurityIncident({
        active: !!payload?.active,
        incident: payload?.incident || null
      });
      setSessionError('');
    } catch (error) {
      setSessionError(error.message || 'Unable to open incident case');
    } finally {
      setIncidentCaseBusy(false);
    }
  };

  const closeIncidentCase = async () => {
    if (incidentCaseBusy || !activeSecurityIncident?.active) return;
    setIncidentCaseBusy(true);
    try {
      await closeSecurityIncident({
        reason: liveSecurityIncident?.title || 'Incident mitigated and closed from UI'
      });
      setActiveSecurityIncident((prev) => ({
        active: false,
        incident: prev?.incident
          ? {
              ...prev.incident,
              closedAt: new Date().toISOString(),
              closeReason: liveSecurityIncident?.title || 'Incident mitigated and closed from UI'
            }
          : prev?.incident
      }));
      setSessionError('');
    } catch (error) {
      setSessionError(error.message || 'Unable to close incident case');
    } finally {
      setIncidentCaseBusy(false);
    }
  };

  const onAuthChange = (event) => {
    const { name, value } = event.target;
    setAuth((prev) => ({ ...prev, [name]: value }));
  };


  const onLogin = async (event) => {
    event.preventDefault();
    try {
      const payload = await login({
        user: auth.user,
        password: auth.password,
        totpCode: totpCode || undefined
      });

      // Check if 2FA is required
      if (payload.status === 'mfa_required' || payload.status === '2fa_required') {
        setTwoFARequired(true);
        setTotpCode('');
        setAvailableMfaMethods(Array.isArray(payload.mfaMethods) ? payload.mfaMethods : (payload.totpEnabled ? ['totp'] : []));
        setWebauthnLoginOptions(payload.webauthn || null);
        setPreferredMfaMethod(String(payload.preferredMfaMethod || 'any'));
        setAuthError('');
        return;
      }

      setTwoFARequired(false);
      setAvailableMfaMethods([]);
      setWebauthnLoginOptions(null);
      setTotpCode('');
      const bootstrap = payload.bootstrap || {};
      setAuth((prev) => ({
        ...prev,
        token: payload.token,
        role: normalizeRole(payload.role),
        user: payload.user,
        permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
        password: ''
      }));
      setAuthToken(payload.token);
      setTotpEnabled(!!payload.totpEnabled);
      setWebauthnEnabled(!!payload.webauthnEnabled);
      setPreferredMfaMethod(String(payload.preferredMfaMethod || 'any'));
      setBootstrapState({
        required: !!bootstrap.required,
        passwordChangeRequired: !!bootstrap.passwordChangeRequired,
        mfaSetupRequired: !!bootstrap.mfaSetupRequired,
        totpEnabled: !!payload.totpEnabled,
        webauthnEnabled: !!payload.webauthnEnabled
      });
      setChangePwCurrent(bootstrap.passwordChangeRequired ? auth.password : '');
      setTotpSetupData(null);
      setTotpQrDataUrl('');
      setTotpSetupCode('');
      setTotpError('');
      setTokenExpiresAt(payload.expiresAt || '');
      localStorage.setItem('endoriumfort_auth', JSON.stringify({
        token: payload.token,
        user: payload.user,
        role: normalizeRole(payload.role),
        permissions: Array.isArray(payload.permissions) ? payload.permissions : []
      }));
      setAuthError('');
      navigate('/');
    } catch (error) {
      setAuthError(error.message || t('auth.loginFailed'));
    }
  };

  const onStartSsoLogin = () => {
    setAuthError('');
    startOidcSso({ provider: ssoLogin.provider || undefined, postLoginRedirect: '/' });
  };

  const onLoginWithPasskey = async () => {
    if (!webauthnLoginOptions) {
      setAuthError(t('auth.noPasskeyChallenge'));
      return;
    }
    setWebauthnBusy(true);
    setAuthError('');
    try {
      const assertion = await getBrowserPasskeyAssertion(webauthnLoginOptions);
      const payload = await login({
        user: auth.user,
        password: auth.password,
        webauthnRequestId: webauthnLoginOptions.requestId,
        webauthnCredentialId: assertion.credentialId,
        webauthnAuthenticatorData: assertion.authenticatorData,
        webauthnClientDataJSON: assertion.clientDataJSON,
        webauthnSignature: assertion.signature
      });
      if (payload.status === 'mfa_required') {
        setWebauthnLoginOptions(payload.webauthn || null);
        throw new Error(payload.message || t('auth.passkeyStillRequired'));
      }
      const bootstrap = payload.bootstrap || {};
      setTwoFARequired(false);
      setAvailableMfaMethods([]);
      setWebauthnLoginOptions(null);
      setTotpCode('');
      setAuth((prev) => ({
        ...prev,
        token: payload.token,
        role: normalizeRole(payload.role),
        user: payload.user,
        permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
        password: ''
      }));
      setAuthToken(payload.token);
      setTotpEnabled(!!payload.totpEnabled);
      setWebauthnEnabled(!!payload.webauthnEnabled);
      setPreferredMfaMethod(String(payload.preferredMfaMethod || 'any'));
      setBootstrapState({
        required: !!bootstrap.required,
        passwordChangeRequired: !!bootstrap.passwordChangeRequired,
        mfaSetupRequired: !!bootstrap.mfaSetupRequired,
        totpEnabled: !!payload.totpEnabled,
        webauthnEnabled: !!payload.webauthnEnabled
      });
      setTokenExpiresAt(payload.expiresAt || '');
      localStorage.setItem('endoriumfort_auth', JSON.stringify({
        token: payload.token,
        user: payload.user,
        role: normalizeRole(payload.role),
        permissions: Array.isArray(payload.permissions) ? payload.permissions : []
      }));
      navigate('/');
    } catch (error) {
      setAuthError(error.message || t('auth.passkeySignInFailed'));
    } finally {
      setWebauthnBusy(false);
    }
  };

  const onLogout = async () => {
    try { await logout(); } catch (_) {}
    setAuth((prev) => ({ ...prev, token: '', password: '', permissions: [] }));
    setAuthToken('');
    setTokenExpiresAt('');
    setBootstrapState({
      required: false,
      passwordChangeRequired: false,
      mfaSetupRequired: false,
      totpEnabled: false,
      webauthnEnabled: false
    });
    setWebauthnEnabled(false);
    setWebauthnCredentials([]);
    setWebauthnLoginOptions(null);
    setAvailableMfaMethods([]);
    setPreferredMfaMethod('any');
    setTotpSetupData(null);
    setTotpQrDataUrl('');
    localStorage.removeItem('endoriumfort_auth');
    navigate('/login');
  };

  const refreshLicenseStatus = async () => {
    try {
      const status = await fetchLicenseStatus();
      setLicenseStatus(status);
      return status;
    } catch (_) {
      return null;
    }
  };

  const onApplyLicense = async () => {
    const token = String(licenseUploadText || '').trim();
    if (!token) {
      setLicenseActionMsg({ error: true, message: locale === 'fr' ? 'Collez un jeton de licence.' : 'Paste a license token.' });
      return;
    }
    setLicenseBusy(true);
    setLicenseActionMsg(null);
    try {
      const res = await applyLicense(token);
      await refreshLicenseStatus();
      setLicenseUploadText('');
      setLicenseActionMsg({
        error: false,
        message: (locale === 'fr' ? 'Licence appliquée : ' : 'License applied: ') +
          `${res.tier || 'free'} / ${res.state}`
      });
    } catch (error) {
      setLicenseActionMsg({ error: true, message: error.message || (locale === 'fr' ? 'Licence invalide.' : 'Invalid license.') });
    } finally {
      setLicenseBusy(false);
    }
  };

  const onReloadLicense = async () => {
    setLicenseBusy(true);
    setLicenseActionMsg(null);
    try {
      await reloadLicense();
      const status = await refreshLicenseStatus();
      setLicenseActionMsg({
        error: false,
        message: (locale === 'fr' ? 'Rechargée depuis le disque : ' : 'Reloaded from disk: ') +
          `${status?.tier || 'free'} / ${status?.state || 'none'}`
      });
    } catch (error) {
      setLicenseActionMsg({ error: true, message: error.message || (locale === 'fr' ? 'Rechargement impossible.' : 'Reload failed.') });
    } finally {
      setLicenseBusy(false);
    }
  };


  const onTerminate = async (sessionId) => {
    try {
      if (readOpenTerminal() === sessionId) forgetOpenTerminal();
      const updated = await terminateSession(sessionId);
      setSessions((prev) =>
        prev.map((item) => (item.id === sessionId ? updated : item))
      );
      loadAudit();
    } catch (error) {
      setSessionError(error.message || t('feedback.unableTerminateSession'));
    }
  };

  const loadAudit = async () => {
    if (!auth.token) {
      setAuditError(t('app.auditorRoleHint'));
      return;
    }
    setLoadingAudit(true);
    try {
      const data = await fetchAudit();
      setAuditItems(Array.isArray(data.items) ? data.items : []);
      setAuditError('');
    } catch (error) {
      setAuditError(error.message || t('feedback.unableLoadAudit'));
    } finally {
      setLoadingAudit(false);
    }
  };

  const openAudit = (sessionId = null) => {
    setAuditFilter(sessionId);
    loadAudit();
  };

  useEffect(() => {
    if (!activeTerminalSession || !terminalRef.current) {
      return undefined;
    }

    const terminal = new Terminal({
      fontFamily: '"Cascadia Mono", Consolas, "IBM Plex Mono", monospace',
      fontSize: 13,
      lineHeight: 1.25,
      cursorBlink: true,
      theme: {
        background: '#101216',
        foreground: '#d4d7dc',
        cursor: '#d4d7dc',
        selectionBackground: '#3a64f055'
      }
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(terminalRef.current);
    try {
      fitAddon.fit();
    } catch (_) {
      // Host not on screen yet; TerminalSlot refits once it is attached.
    }

    terminalInstanceRef.current = terminal;
    fitAddonRef.current = fitAddon;
    setTerminalReady(true);

    const handleResize = () => {
      if (!fitAddonRef.current || !terminalInstanceRef.current) {
        return;
      }
      fitAddonRef.current.fit();
      if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
        socketRef.current.send(
          JSON.stringify({
            type: 'resize',
            cols: terminalInstanceRef.current.cols,
            rows: terminalInstanceRef.current.rows
          })
        );
      }
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (terminalInputListenerRef.current) {
        terminalInputListenerRef.current.dispose();
        terminalInputListenerRef.current = null;
      }
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
      terminal.dispose();
      terminalInstanceRef.current = null;
      fitAddonRef.current = null;
      setTerminalReady(false);
    };
  }, [activeTerminalSession]);

  useEffect(() => {
    if (!autoConnectSessionId) return;
    if (!terminalReady) return;
    if (!auth.token || (!sshPassword && resumeSessionId !== autoConnectSessionId)) return;
    if (!activeTerminalSession || activeTerminalSession.id !== autoConnectSessionId) return;

    setAutoConnectSessionId(null);
    connectTerminal();
  }, [
    autoConnectSessionId,
    terminalReady,
    auth.token,
    sshPassword,
    activeTerminalSession,
    resumeSessionId
  ]);

  // After a page reload: reopen the terminal of the SSH session this tab had
  // open, if it is still running. The server kept the shell for a grace
  // period (ENDORIUMFORT_SSH_RESUME_GRACE_SECONDS) and hands it back.
  const resumeCheckedRef = useRef(false);
  useEffect(() => {
    if (resumeCheckedRef.current || !auth.token || activeTerminalSession || !sessions.length) return;
    resumeCheckedRef.current = true;
    let id = 0;
    try { id = Number(sessionStorage.getItem(OPEN_TERMINAL_KEY)) || 0; } catch (_) { /* storage unavailable */ }
    if (!id) return;
    const session = sessions.find((item) => item.id === id);
    const isSsh = String(session?.protocol || '').toLowerCase() === 'ssh';
    if (!session || session.status !== 'active' || !isSsh) {
      forgetOpenTerminal();
      return;
    }
    openTerminal(session, { resume: true });
  }, [auth.token, sessions, activeTerminalSession]);

  const resolveSessionResource = (session) => {
    if (!session) return null;
    const sessionResourceId = Number(session.resourceId) || 0;
    if (sessionResourceId > 0) {
      const byId = resources.find((item) => Number(item.id) === sessionResourceId);
      if (byId) return byId;
    }

    const sessionTarget = String(session.target || '').trim();
    const sessionProtocol = String(session.protocol || '').toLowerCase();
    const sessionPort = Number(session.port) || 0;

    return resources.find((item) => {
      const resourceTarget = String(item.target || '').trim();
      const resourceProtocol = String(item.protocol || '').toLowerCase();
      const resourcePort = Number(item.port) || 0;
      if (!resourceTarget || !resourceProtocol || resourcePort <= 0) {
        return false;
      }
      return (
        resourceTarget === sessionTarget &&
        resourceProtocol === sessionProtocol &&
        resourcePort === sessionPort
      );
    }) || null;
  };

  useEffect(() => {
    // Relay lookups are licensed; without the license they would only raise upsell prompts.
    if (!auth.token || !sessions.length || !relaysLicensed) {
      setSessionRelayHints({});
      return;
    }

    const resourceIds = Array.from(
      new Set(
        sessions
          .map((session) => Number(resolveSessionResource(session)?.id) || 0)
          .filter((id) => id > 0)
      )
    );

    if (!resourceIds.length) {
      setSessionRelayHints({});
      return;
    }

    let active = true;
    Promise.all(
      resourceIds.map(async (resourceId) => {
        try {
          const data = await fetchRelayResolution(resourceId);
          return [resourceId, data];
        } catch (_) {
          return [resourceId, null];
        }
      })
    )
      .then((entries) => {
        if (!active) return;
        const resolutionByResourceId = {};
        entries.forEach(([resourceId, data]) => {
          resolutionByResourceId[resourceId] = data;
        });

        const hints = {};
        sessions.forEach((session) => {
          const resourceId = Number(resolveSessionResource(session)?.id) || 0;
          if (!resourceId) return;
          const resolution = resolutionByResourceId[resourceId];
          const route = String(resolution?.route || 'direct').toLowerCase() === 'relay' ? 'relay' : 'direct';
          const relayLabel = resolution?.relay?.label || resolution?.relay?.relayId || '';
          const relayStatus = String(resolution?.relay?.status || '').toLowerCase() || 'offline';
          hints[session.id] = {
            route,
            relayLabel,
            relayStatus,
            relayAssigned: !!resolution?.relayAssigned
          };
        });
        setSessionRelayHints(hints);
      })
      .catch(() => {
        if (!active) return;
        setSessionRelayHints({});
      });

    return () => {
      active = false;
    };
  }, [auth.token, sessions, resources, relaysLicensed]);

  const openTerminal = async (session, { resume = false } = {}) => {
    setActiveTerminalSession(session);
    setSshPassword('');
    setTerminalError('');
    setTerminalInfo('');
    setTerminalStatus('idle');
    setTerminalReady(false);

    if (resume) {
      setResumeSessionId(session.id);
      setAutoConnectSessionId(session.id);
      setTerminalInfo(t('feedback.sessionResuming'));
      return;
    }
    setResumeSessionId(null);

    const resource = resolveSessionResource(session);
    if (!resource || !resource.hasCredentials) {
      setTerminalInfo(t('feedback.manualPasswordRequired'));
      return;
    }

    if ((resource.credentialSource || session.credentialSource || 'vaulted') !== 'vaulted') {
      setAutoConnectSessionId(session.id);
      setTerminalInfo('Brokered session ready. Credentials stay on the bastion.');
      return;
    }

    setTerminalInfo(t('feedback.autoReconnectAttempt'));

    try {
      const lease = await issueEphemeralCredential(resource.id);
      const creds = await consumeEphemeralCredential(lease.leaseId);
      if (creds.sshPassword) {
        setSshPassword(creds.sshPassword);
        setAutoConnectSessionId(session.id);
        setTerminalInfo(t('feedback.vaultCredentialsLoaded'));
      }
    } catch (_) {
      setTerminalInfo(t('feedback.automaticCredentialRecoveryFailed'));
    }
  };

  const buildWebSocketUrl = (path, params = {}) => {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = new URL(path, window.location.origin);
    url.protocol = wsProtocol;
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value));
      }
    });
    return url.toString();
  };

  const connectTerminal = () => {
    setTerminalInfo('');
    if (!activeTerminalSession) {
      setTerminalError(t('feedback.pickSessionToConnect'));
      return;
    }
    if (!sshPassword && activeTerminalSession.id !== resumeSessionId) {
      setTerminalError(t('feedback.sshPasswordRequired'));
      return;
    }
    if (!auth.token) {
      setTerminalError(t('feedback.signInFirst'));
      return;
    }

    const terminal = terminalInstanceRef.current;
    if (!terminal) {
      setTerminalError(t('feedback.terminalInitializing'));
      window.setTimeout(() => {
        if (terminalInstanceRef.current && auth.token && activeTerminalSession) {
          connectTerminal();
        }
      }, 150);
      return;
    }

    const wsUrl = buildWebSocketUrl('/api/ws/ssh');

    // Prevent duplicated key forwarding when reconnecting to the same terminal.
    if (terminalInputListenerRef.current) {
      terminalInputListenerRef.current.dispose();
      terminalInputListenerRef.current = null;
    }
    if (socketRef.current) {
      socketRef.current.close();
      socketRef.current = null;
    }

    const socket = new WebSocket(wsUrl);
    let socketOpened = false;
    socket.binaryType = 'arraybuffer';
    socketRef.current = socket;
    setTerminalStatus('connecting');

    socket.addEventListener('open', () => {
      if (socketRef.current !== socket) return;
      socketOpened = true;
      setTerminalStatus('live');
      terminal.focus();
      rememberOpenTerminal(activeTerminalSession.id);
      socket.send(
        JSON.stringify({
          type: 'start',
          sessionId: activeTerminalSession.id,
          password: sshPassword,
          cols: terminal.cols,
          rows: terminal.rows
        })
      );
      terminalInputListenerRef.current = terminal.onData((data) => {
        if (socket.readyState === WebSocket.OPEN) {
          // Some remote shells expect backspace as Ctrl-H (^H) instead of DEL.
          const normalizedInput = data.replace(/\x7f/g, '\b');
          socket.send(JSON.stringify({ type: 'input', data: normalizedInput }));
        }
      });
    });

    socket.addEventListener('message', (event) => {
      if (socketRef.current !== socket) return;
      if (typeof event.data === 'string') {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'status' && payload.message === 'Session resumed') {
            setResumeSessionId(null);
            setTerminalInfo(t('feedback.sessionResumed'));
          } else if (payload.type === 'status' && payload.message === 'SSH closed') {
            forgetOpenTerminal();
          }
          if (payload.type === 'error') {
            forgetOpenTerminal();
            setResumeSessionId(null);
            // The server keeps the socket open after an SSH error, so the
            // status has to follow the message, not the socket.
            const known = {
              'Unable to resolve host': 'feedback.sshHostUnknown',
              'Unable to connect': 'feedback.sshUnreachable',
              'SSH handshake failed': 'feedback.sshHandshake',
              'SSH authentication failed': 'feedback.sshAuthFailed',
              'No SSH credential available for this session': 'feedback.sshNoCredential'
            };
            setTerminalStatus('error');
            setTerminalError(known[payload.message] ? t(known[payload.message]) : payload.message || t('feedback.sshError'));
          }
        } catch (error) {
          terminal.write(event.data);
        }
        return;
      }
      const decoder = new TextDecoder();
      terminal.write(decoder.decode(event.data));
    });

    socket.addEventListener('close', (event) => {
      if (socketRef.current !== socket) return;
      if (terminalInputListenerRef.current) {
        terminalInputListenerRef.current.dispose();
        terminalInputListenerRef.current = null;
      }
      socketRef.current = null;
      if (!socketOpened) {
        setTerminalStatus('error');
        setTerminalError(t('feedback.sshRejected'));
        return;
      }
      if (event?.code === 1008 || event?.code === 1006) {
        setTerminalStatus('error');
        setTerminalError(t('feedback.sshInterrupted'));
        return;
      }
      setTerminalStatus('closed');
    });

    socket.addEventListener('error', () => {
      if (socketRef.current !== socket) return;
      setTerminalStatus('error');
      setTerminalError(t('feedback.websocketTransportError'));
    });
  };

  // Re-measure the terminal after it was hidden, moved or went fullscreen.
  const refitTerminal = () => {
    const terminal = terminalInstanceRef.current;
    if (!fitAddonRef.current || !terminal || !terminal.element?.isConnected) return;
    try {
      fitAddonRef.current.fit();
    } catch (_) {
      return;
    }
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify({ type: 'resize', cols: terminal.cols, rows: terminal.rows }));
    }
  };

  const sendSnippetToTerminal = (snippet, execute = false) => {
    if (!snippet?.command) return;
    const socket = socketRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      setTerminalError(t('feedback.connectTerminalBeforeSnippets'));
      return;
    }
    const payload = execute ? `${snippet.command}\n` : snippet.command;
    socket.send(JSON.stringify({ type: 'input', data: payload }));
    setTerminalInfo(
      execute
        ? t('feedback.snippetExecuted', { label: snippet.label })
        : t('feedback.snippetInjected', { label: snippet.label })
    );
  };

  const addCustomSnippet = () => {
    const label = snippetLabel.trim();
    const command = snippetCommand.trim();
    if (!label || !command) {
      setTerminalError(t('feedback.snippetRequired'));
      return;
    }
    const id = `custom-${Date.now()}`;
    setCustomSnippets((prev) => [...prev, { id, label, command }]);
    setSnippetLabel('');
    setSnippetCommand('');
    setTerminalError('');
    setTerminalInfo(t('feedback.snippetSaved', { label }));
  };

  const removeCustomSnippet = (snippetId) => {
    setCustomSnippets((prev) => prev.filter((item) => item.id !== snippetId));
  };

  const clearAgentLaunchWatcher = () => {
    if (agentLaunchTimeoutRef.current) {
      window.clearTimeout(agentLaunchTimeoutRef.current);
      agentLaunchTimeoutRef.current = null;
    }
    if (typeof agentLaunchCleanupRef.current === 'function') {
      agentLaunchCleanupRef.current();
      agentLaunchCleanupRef.current = null;
    }
  };

  const isAgentTunnelProtocol = (protocol) => {
    const normalized = String(protocol || '').toLowerCase();
    // SSH keeps the in-browser web terminal; only "agent" tunnels and direct RDP
    // (which has no web viewer) launch via the native agent deep link.
    return normalized === 'agent' || normalized === 'rdp';
  };

  const resolveAgentInstallGuide = () => {
    const ua = String(navigator.userAgent || '').toLowerCase();
    if (ua.includes('windows')) {
      return {
        platform: 'Windows',
        command: '.\\agent\\installers\\windows\\install-protocol.ps1 -AgentPath .\\agent\\endoriumfort-agent.exe'
      };
    }
    if (ua.includes('mac os') || ua.includes('macintosh') || ua.includes('darwin')) {
      return {
        platform: 'macOS',
        command: './agent/installers/macos/install-protocol.sh ./agent/endoriumfort-agent-darwin-arm64'
      };
    }
    return {
      platform: 'Linux',
      command: './agent/installers/linux/install-protocol.sh ./agent/endoriumfort-agent'
    };
  };

  const buildAgentLaunchPayload = async (resource, localPort, sessionId) => {
    const normalizedOrigin = String(window.location.origin || '').replace(/\/$/, '');
    const resourceProtocol = String(resource?.protocol || '').toLowerCase();
    // For "agent" resources the tunnelled protocol + user are configured on the
    // resource (agentProtocol / sshUsername) and injected as &protocol / &user;
    // for direct rdp/vnc resources they come from the protocol itself.
    const effectiveProtocol =
      resourceProtocol === 'agent'
        ? String(resource?.agentProtocol || 'tcp').toLowerCase()
        : resourceProtocol;
    const tunnelUser = String(resource?.sshUsername || '').trim();
    // ssh/rdp/vnc launch a native client; http/https/tcp expose a local web app.
    const openInBrowser =
      effectiveProtocol === 'http' || effectiveProtocol === 'https' || effectiveProtocol === 'tcp';
    const localEndpoint = `127.0.0.1:${localPort}`;
    const localUrl = `http://127.0.0.1:${localPort}`;
    const params = new URLSearchParams();
    params.set('server', normalizedOrigin);
    params.set('resource', String(resource.id));
    params.set('local-port', String(localPort));
    params.set('protocol', effectiveProtocol);
    // Generic &user (the agent maps it to the SSH user) plus the protocol-specific
    // param the native client expects, so it launches without prompting.
    if (tunnelUser) {
      params.set('user', tunnelUser);
      if (effectiveProtocol === 'ssh') params.set('ssh-user', tunnelUser);
      if (effectiveProtocol === 'rdp') params.set('rdp-user', tunnelUser);
    }
    if (openInBrowser) {
      params.set('redirect-url', localUrl);
    } else {
      params.set('no-browser', '1');
    }
    // Embed a SHORT-LIVED token bound to the session (never the long-lived
    // session token): deep links leak via browser history/logs, and the server
    // only lets the agent open tunnels under that session.
    const minted = await mintAgentToken(sessionId);
    const linkToken = minted?.token || '';
    if (!linkToken) throw new Error(t('feedback.agentTokenUnavailable'));
    params.set('token', linkToken);

    return {
      localUrl,
      localEndpoint,
      openInBrowser,
      installGuide: resolveAgentInstallGuide(),
      command: `endoriumfort-agent connect --server ${normalizedOrigin} --token ${linkToken || '<token>'} --resource ${resource.id} --local-port ${localPort}`,
      deepLink: `endoriumfort://connect?${params.toString()}`
    };
  };

  const launchAgentDeepLink = (deepLink) => {
    if (!deepLink) return;
    clearAgentLaunchWatcher();
    setAgentModal((prev) => (prev ? { ...prev, launchState: 'opening' } : prev));

    const onHidden = () => {
      if (document.visibilityState === 'hidden') {
        clearAgentLaunchWatcher();
        setAgentModal((prev) => (prev ? { ...prev, launchState: 'opened' } : prev));
      }
    };

    const onPageHide = () => {
      clearAgentLaunchWatcher();
      setAgentModal((prev) => (prev ? { ...prev, launchState: 'opened' } : prev));
    };

    document.addEventListener('visibilitychange', onHidden);
    window.addEventListener('pagehide', onPageHide, { once: true });
    agentLaunchCleanupRef.current = () => {
      document.removeEventListener('visibilitychange', onHidden);
      window.removeEventListener('pagehide', onPageHide);
    };

    agentLaunchTimeoutRef.current = window.setTimeout(() => {
      clearAgentLaunchWatcher();
      setAgentModal((prev) => (prev ? { ...prev, launchState: 'fallback' } : prev));
    }, 1600);

    window.location.href = deepLink;
  };

  useEffect(() => {
    return () => {
      clearAgentLaunchWatcher();
    };
  }, []);

  // Why the last connection attempt failed (server message), so a refusal for
  // missing access details can reopen the access dialog instead.
  const lastConnectErrorRef = useRef('');

  const connectToResource = async (resource, accessMeta = {}) => {
    lastConnectErrorRef.current = '';
    if (!auth.token) {
      setSessionError(t('feedback.signInFirst'));
      return false;
    }

    const protocol = String(resource.protocol || '').toLowerCase();

    // Handle web resources via Remote Browser Isolation (RBI): create a session
    // and open a server-side headless Chromium streamed as pixels. The target
    // site never touches the operator's browser, and apps that break under
    // subpath proxying (Zabbix, etc.) render exactly as they would natively.
    if (protocol === 'http' || protocol === 'https') {
      // Open the isolated-browser tab synchronously (inside the click gesture) so
      // it isn't popup-blocked; navigate it to the decoration-free full-screen RBI
      // page once the session exists. If the browser blocks it, fall back to the
      // in-app modal.
      const rbiTab = window.open('about:blank', '_blank');
      try {
        const payload = {
          resourceId: resource.id,
          target: resource.target,
          user: resource.httpUsername || auth.user,
          protocol: resource.protocol,
          port: resource.port,
          justification: (accessMeta.justification || '').trim(),
          ticketId: (accessMeta.ticketId || '').trim(),
          purpose: (accessMeta.purpose || '').trim(),
          purposeEvidence: (accessMeta.purposeEvidence || '').trim(),
          accessRequestId: accessMeta.accessRequestId || undefined
        };
        const created = await createSession(payload);
        setSessions((prev) => [created, ...prev]);
        if (created?.accessGrantId && jitLicensed) {
          fetchAccessGrants()
            .then((data) => {
              setAccessGrants(Array.isArray(data?.items) ? data.items : []);
            })
            .catch(() => {});
        }
        setSessionError('');
        setVncViewerSession(null);
        if (rbiTab) {
          rbiTab.location = `${window.location.origin}/?rbi=${created.id}`;
        } else {
          setRbiViewerSession(created);
        }
        return true;
      } catch (error) {
        if (rbiTab) rbiTab.close();
        lastConnectErrorRef.current = error.message || '';
        setSessionError(error.message || 'Unable to create session');
        return false;
      }
    }

    if (protocol === 'vnc') {
      try {
        const payload = {
          resourceId: resource.id,
          target: resource.target,
          user: resource.sshUsername || auth.user,
          protocol: resource.protocol,
          port: resource.port,
          justification: (accessMeta.justification || '').trim(),
          ticketId: (accessMeta.ticketId || '').trim(),
          purpose: (accessMeta.purpose || '').trim(),
          purposeEvidence: (accessMeta.purposeEvidence || '').trim(),
          accessRequestId: accessMeta.accessRequestId || undefined
        };
        const created = await createSession(payload);
        setSessions((prev) => [created, ...prev]);
        if (created?.accessGrantId && jitLicensed) {
          fetchAccessGrants()
            .then((data) => {
              setAccessGrants(Array.isArray(data?.items) ? data.items : []);
            })
            .catch(() => {});
        }
        setSessionError('');
        setVncViewerSession(created);
        return true;
      } catch (error) {
        lastConnectErrorRef.current = error.message || '';
        setSessionError(error.message || 'Unable to create session');
        return false;
      }
    }

    // Handle protocols that should use local TCP tunnel through the agent. The
    // tunnel runs under a session opened here, so the server applies the same
    // access rules (reason, ticket, purpose, approval) and records it.
    if (isAgentTunnelProtocol(resource.protocol)) {
      try {
        const payload = {
          resourceId: resource.id,
          target: resource.target,
          user: resource.sshUsername || auth.user,
          protocol: resource.protocol,
          port: resource.port,
          justification: (accessMeta.justification || '').trim(),
          ticketId: (accessMeta.ticketId || '').trim(),
          purpose: (accessMeta.purpose || '').trim(),
          purposeEvidence: (accessMeta.purposeEvidence || '').trim(),
          accessRequestId: accessMeta.accessRequestId || undefined
        };
        const created = await createSession(payload);
        setSessions((prev) => [created, ...prev]);
        if (created?.accessGrantId && jitLicensed) {
          fetchAccessGrants()
            .then((data) => {
              setAccessGrants(Array.isArray(data?.items) ? data.items : []);
            })
            .catch(() => {});
        }
        const randomPort = 10000 + Math.floor(Math.random() * 50000);
        const launchPayload = await buildAgentLaunchPayload(resource, randomPort, created.id);
        setSessionError('');
        setAgentModal({ resource, sessionId: created.id, port: randomPort, copied: 'idle', linkCopied: 'idle', installCopied: 'idle', launchState: 'opening', ...launchPayload });
        launchAgentDeepLink(launchPayload.deepLink);
        return true;
      } catch (error) {
        lastConnectErrorRef.current = error.message || '';
        setSessionError(error.message || 'Unable to create session');
        return false;
      }
    }

    // Handle SSH/other protocols
    try {
      const payload = {
        resourceId: resource.id,
        target: resource.target,
        user: resource.sshUsername || auth.user,
        protocol: resource.protocol,
        port: resource.port,
        justification: (accessMeta.justification || '').trim(),
        ticketId: (accessMeta.ticketId || '').trim(),
        purpose: (accessMeta.purpose || '').trim(),
        purposeEvidence: (accessMeta.purposeEvidence || '').trim(),
        accessRequestId: accessMeta.accessRequestId || undefined
      };
      const created = await createSession(payload);
      setSessions((prev) => [created, ...prev]);
      if (created?.accessGrantId && jitLicensed) {
        fetchAccessGrants()
          .then((data) => {
            setAccessGrants(Array.isArray(data?.items) ? data.items : []);
          })
          .catch(() => {});
      }
      setSessionError('');
      openTerminal(created);

      // Auto-inject credentials only for vaulted mode.
      if (resource.hasCredentials && (resource.credentialSource || 'vaulted') === 'vaulted') {
        try {
          const lease = await issueEphemeralCredential(resource.id);
          const creds = await consumeEphemeralCredential(lease.leaseId);
          if (creds.sshPassword) {
            setSshPassword(creds.sshPassword);
            setAutoConnectSessionId(created.id);
          }
        } catch (_) {
          // JIT-first: if lease issuance fails, fall back to manual password entry.
        }
      } else if ((resource.credentialSource || 'vaulted') !== 'vaulted') {
        setSshPassword('');
        setAutoConnectSessionId(created.id);
      }
      return true;
    } catch (error) {
      lastConnectErrorRef.current = error.message || '';
      setSessionError(error.message || 'Unable to create session');
      return false;
    }
  };

  const closeAccessPrompt = () => {
    setAccessPromptResource(null);
    setAccessPromptReason('');
    setAccessPromptTicketId('');
    setAccessPromptPurpose('');
    setAccessPromptPurposeEvidence('');
    setAccessPromptMode('connect');
    setAccessPromptRequestId(null);
    setRiskPreview(null);
    setRiskPreviewError('');
  };

  // The access dialog only opens when the server will ask for something
  // (reason, ticket, purpose); otherwise "Connexion immédiate" means it.
  // What the server will ask before opening a session: an approved request
  // (resource setting or JIT policy) and/or details in the access dialog.
  const accessNeeds = async (resource) => {
    const risk = String(resource?.riskLevel || '').toLowerCase();
    const local = !!(resource.requireAccessJustification || risk === 'high' || risk === 'critical' || containmentEnabled);
    if (!jitLicensed) return { approval: !!resource.requireDualApproval, prompt: local };
    try {
      const preview = await previewSessionRisk({ resourceId: resource.id, justification: '', ticketId: '', purpose: '' });
      return {
        approval: !!(resource.requireDualApproval || preview?.approvalRequired),
        prompt: local || !!(preview?.justificationRequired || preview?.ticketRequired || preview?.purposeRequired)
      };
    } catch {
      return { approval: !!resource.requireDualApproval, prompt: true };
    }
  };

  // Server refusals that the access dialog can fix (see POST /api/sessions).
  const MISSING_ACCESS_DETAILS = /requires an access justification|requires a ticketId|require a purpose|provide a justification/i;

  const openConnectPrompt = (resource) => {
    const existingPlaybook =
      accessPlaybooks.find((item) => Number(item.resourceId) === Number(resource.id)) || null;
    setAccessPromptMode('connect');
    setAccessPromptResource(resource);
    setSessionError('');
    setAccessPromptReason(existingPlaybook?.justification || '');
    setAccessPromptTicketId(existingPlaybook?.ticketId || '');
    setAccessPromptPurpose(existingPlaybook?.purpose || '');
    setAccessPromptPurposeEvidence(existingPlaybook?.purposeEvidence || '');
    setRiskPreview(null);
    setRiskPreviewError('');
  };

  const onConnectResource = async (resource) => {
    // Every protocol opens a session on the bastion (web ones through the
    // isolated browser, agent tunnels before the deep link), so each can carry
    // a reason, ticket and purpose.

    const needs = await accessNeeds(resource);
    if (needs.approval && !canManagePlatform) {
      const existingPlaybook =
        accessPlaybooks.find((item) => Number(item.resourceId) === Number(resource.id)) || null;
      const approved = accessRequests.find(
        (item) =>
          item.resourceId === resource.id &&
          item.requester === auth.user &&
          item.status === 'approved'
      );
      if (approved && !needs.prompt) {
        await connectToResource(resource, {
          justification: approved.justification || '',
          ticketId: approved.ticketId || '',
          accessRequestId: approved.id
        });
        return;
      }
      if (approved) {
        // Approved, but the session still needs a purpose or a ticket.
        setAccessPromptMode('connect');
        setAccessPromptRequestId(approved.id);
        setAccessPromptResource(resource);
        setSessionError('');
        setAccessPromptReason(approved.justification || '');
        setAccessPromptTicketId(approved.ticketId || '');
        setAccessPromptPurpose(existingPlaybook?.purpose || '');
        setAccessPromptPurposeEvidence(existingPlaybook?.purposeEvidence || '');
        setRiskPreview(null);
        setRiskPreviewError('');
        return;
      }
      setAccessPromptMode('request');
      setAccessPromptResource(resource);
      setSessionError('');
      setAccessPromptReason(existingPlaybook?.justification || '');
      setAccessPromptTicketId(existingPlaybook?.ticketId || '');
      setAccessPromptPurpose(existingPlaybook?.purpose || '');
      setAccessPromptPurposeEvidence(existingPlaybook?.purposeEvidence || '');
      setRiskPreview(null);
      setRiskPreviewError('');
      return;
    }

    if (!needs.prompt) {
      const connected = await connectToResource(resource);
      // The server asked for details the client did not foresee (a rule it
      // could not preview): ask for them rather than leaving an error.
      if (!connected && MISSING_ACCESS_DETAILS.test(lastConnectErrorRef.current)) openConnectPrompt(resource);
      return;
    }

    openConnectPrompt(resource);
  };

  // "Resume" on one of the user's active sessions: back to the SSH terminal, or
  // a fresh agent link for a tunnel (still tied to that session).
  const resumeSession = async (session) => {
    const protocol = String(session?.protocol || '').toLowerCase();
    if (protocol === 'ssh') {
      openTerminal(session);
      return;
    }
    if (!isAgentTunnelProtocol(protocol)) return;
    const resource = resources.find((item) => Number(item.id) === Number(session.resourceId));
    if (!resource) return;
    try {
      const randomPort = 10000 + Math.floor(Math.random() * 50000);
      const launchPayload = await buildAgentLaunchPayload(resource, randomPort, session.id);
      setSessionError('');
      setAgentModal({ resource, sessionId: session.id, port: randomPort, copied: 'idle', linkCopied: 'idle', installCopied: 'idle', launchState: 'opening', ...launchPayload });
      launchAgentDeepLink(launchPayload.deepLink);
    } catch (error) {
      setSessionError(error.message || t('feedback.agentTokenUnavailable'));
    }
  };

  const openLiveSession = async (session) => {
    const protocol = String(session?.protocol || '').toLowerCase();
    if (protocol === 'vnc') {
      setVncViewerSession(session);
      return;
    }
    await openTerminal(session);
  };

  const applyCurrentAccessPlaybook = () => {
    if (!currentAccessPlaybook) {
      setSessionError(locale === 'fr' ? 'Aucun playbook enregistré pour cette ressource.' : 'No saved playbook for this resource.');
      return;
    }
    setAccessPromptReason(currentAccessPlaybook.justification || '');
    setAccessPromptTicketId(currentAccessPlaybook.ticketId || '');
    setAccessPromptPurpose(currentAccessPlaybook.purpose || '');
    setAccessPromptPurposeEvidence(currentAccessPlaybook.purposeEvidence || '');
    setSessionError('');
  };

  const saveCurrentAccessPlaybook = () => {
    const resourceId = Number(accessPromptResource?.id) || 0;
    if (!resourceId) return;
    const playbook = {
      resourceId,
      justification: accessPromptReason.trim(),
      ticketId: accessPromptTicketId.trim(),
      purpose: accessPromptPurpose.trim(),
      purposeEvidence: accessPromptPurposeEvidence.trim(),
      updatedAt: new Date().toISOString()
    };
    if (!playbook.justification && !playbook.ticketId && !playbook.purpose && !playbook.purposeEvidence) {
      setSessionError(locale === 'fr' ? 'Le playbook ne peut pas être vide. Remplissez au moins un champ avant enregistrement.' : 'Playbook cannot be empty. Fill at least one field before saving.');
      return;
    }
    setAccessPlaybooks((prev) => {
      const next = prev.filter((item) => Number(item.resourceId) !== resourceId);
      return [...next, playbook];
    });
    setSessionError('');
    setTerminalInfo(
      locale === 'fr'
        ? `Playbook d'accès enregistré pour ${accessPromptResource?.name || 'la ressource'}.`
        : `Access playbook saved for ${accessPromptResource?.name || 'resource'}.`
    );
  };

  const deleteCurrentAccessPlaybook = () => {
    const resourceId = Number(accessPromptResource?.id) || 0;
    if (!resourceId) return;
    setAccessPlaybooks((prev) => prev.filter((item) => Number(item.resourceId) !== resourceId));
    setSessionError('');
  };

  const onSubmitAccessPrompt = async (event) => {
    event.preventDefault();
    if (!accessPromptResource) {
      return;
    }
    const reason = accessPromptReason.trim();
    const reasonRequired = accessPromptMode === 'request' || accessPromptResource.requireAccessJustification ||
      containmentEnabled || !!riskPreview?.justificationRequired;
    if (reasonRequired && !reason) {
      setSessionError(
        containmentEnabled
          ? (locale === 'fr' ? "Une raison d'accès est requise tant que le mode confinement est actif." : 'Access reason is required while containment mode is active.')
          : (locale === 'fr' ? "Une raison d'accès est requise pour cette ressource." : 'Access reason is required for this resource.')
      );
      return;
    }
    const purpose = accessPromptPurpose.trim();
    const purposeEvidence = accessPromptPurposeEvidence.trim();
    const riskLevel = String(accessPromptResource.riskLevel || '').toLowerCase();
    // The purpose belongs to the session, not to the request: the dialog does
    // not show it when requesting, and it is asked when connecting once the
    // request is approved.
    const purposeRequired = accessPromptMode !== 'request' && (riskLevel === 'high' || riskLevel === 'critical');
    if (purposeRequired && !purpose) {
      setSessionError(locale === 'fr' ? 'Les ressources à haut risque exigent un objectif.' : 'High-risk resources require a purpose.');
      return;
    }
    if (accessPromptMode === 'request') {
      try {
        const created = await createAccessRequest({
          resourceId: accessPromptResource.id,
          justification: reason,
          ticketId: accessPromptTicketId.trim()
        });
        setAccessRequests((prev) => [created, ...prev]);
        setSessionError('');
        closeAccessPrompt();
        // The request page shows it as pending with its history.
        navigate('/demandes');
        return;
      } catch (error) {
        setSessionError(error.message || (locale === 'fr' ? "Impossible d'envoyer la demande d'accès" : 'Unable to submit access request'));
        return;
      }
    }
    const connected = await connectToResource(accessPromptResource, {
      justification: reason,
      ticketId: accessPromptTicketId.trim(),
      purpose,
      purposeEvidence,
      accessRequestId: accessPromptRequestId || undefined
    });
    if (connected) {
      closeAccessPrompt();
    }
  };

  useEffect(() => {
    // The risk preview is part of JIT governance: without it the server answers
    // 403 and the upsell modal would open over the connection dialog.
    if (!accessPromptResource || !auth.token || !jitLicensed) {
      setRiskPreview(null);
      setRiskPreviewError('');
      return undefined;
    }
    const timer = window.setTimeout(async () => {
      setRiskPreviewLoading(true);
      try {
        const data = await previewSessionRisk({
          resourceId: accessPromptResource.id,
          justification: accessPromptReason.trim(),
          ticketId: accessPromptTicketId.trim(),
          purpose: accessPromptPurpose.trim()
        });
        setRiskPreview(data);
        setRiskPreviewError('');
      } catch (error) {
        setRiskPreview(null);
        setRiskPreviewError(error.message || (locale === 'fr' ? "Impossible de calculer l'aperçu de risque" : 'Unable to compute risk preview'));
      } finally {
        setRiskPreviewLoading(false);
      }
    }, 220);

    return () => {
      window.clearTimeout(timer);
    };
  }, [
    accessPromptResource,
    accessPromptReason,
    accessPromptTicketId,
    accessPromptPurpose,
    auth.token,
    jitLicensed
  ]);

  const onApproveAccessRequest = async (requestId) => {
    try {
      const updated = await approveAccessRequest(requestId);
      setAccessRequests((prev) =>
        prev.map((item) => (item.id === requestId ? updated : item))
      );
      setAccessRequestError('');
    } catch (error) {
      setAccessRequestError(error.message || (locale === 'fr' ? "Impossible d'approuver la demande d'accès" : 'Unable to approve access request'));
    }
  };

  const reloadAccessRequests = async () => {
    if (!auth.token || !jitLicensed) return;
    setLoadingAccessRequests(true);
    try {
      const data = await fetchAccessRequests();
      setAccessRequests(Array.isArray(data.items) ? data.items : []);
      setAccessRequestError('');
    } catch (error) {
      setAccessRequestError(error.message || 'Unable to load access requests');
    } finally {
      setLoadingAccessRequests(false);
    }
  };

  const onDenyAccessRequest = async (requestId) => {
    try {
      const updated = await denyAccessRequest(requestId);
      setAccessRequests((prev) =>
        prev.map((item) => (item.id === requestId ? updated : item))
      );
      setAccessRequestError('');
    } catch (error) {
      setAccessRequestError(error.message || (locale === 'fr' ? "Impossible de refuser la demande d'accès" : 'Unable to deny access request'));
    }
  };



  // ── 2FA handlers ──

  const onSetup2FA = async () => {
    setTotpError('');
    try {
      const data = await setup2FA();
      setTotpSetupData(data);
    } catch (error) {
      setTotpError(error.message || t('feedback.failedSetup2fa'));
    }
  };

  const onVerify2FA = async () => {
    setTotpError('');
    try {
      const data = await verify2FA(totpSetupCode);
      setTotpEnabled(true);
      // The server does not always echo the key state: keep ours, then re-read it.
      if ('webauthnEnabled' in data) setWebauthnEnabled(!!data.webauthnEnabled);
      if (data.preferredMfaMethod) setPreferredMfaMethod(String(data.preferredMfaMethod));
      setTotpSetupData(null);
      setTotpQrDataUrl('');
      setTotpSetupCode('');
      setTotpError('');
      const bootstrap = data.bootstrap || {};
      setBootstrapState({
        required: !!bootstrap.required,
        passwordChangeRequired: !!bootstrap.passwordChangeRequired,
        mfaSetupRequired: !!bootstrap.mfaSetupRequired,
        totpEnabled: true,
        webauthnEnabled: 'webauthnEnabled' in data ? !!data.webauthnEnabled : webauthnEnabled
      });
      onLoad2FAStatus();
    } catch (error) {
      setTotpError(error.message || t('feedback.invalidCode'));
    }
  };

  const onDisable2FA = async () => {
    setTotpError('');
    try {
      const data = await disable2FA(totpDisableCode);
      setTotpEnabled(false);
      // The server does not always echo the key state: keep ours, then re-read it.
      if ('webauthnEnabled' in data) setWebauthnEnabled(!!data.webauthnEnabled);
      if (data.preferredMfaMethod) setPreferredMfaMethod(String(data.preferredMfaMethod));
      setTotpDisableCode('');
      setTotpError('');
      const keysLeft = 'webauthnEnabled' in data ? !!data.webauthnEnabled : webauthnEnabled;
      setBootstrapState((prev) => ({
        ...prev,
        mfaSetupRequired: !keysLeft,
        totpEnabled: false,
        webauthnEnabled: keysLeft
      }));
      onLoad2FAStatus();
    } catch (error) {
      setTotpError(error.message || t('feedback.invalidCode'));
    }
  };

  const onLoad2FAStatus = async () => {
    try {
      const data = await get2FAStatus();
      setTotpEnabled(!!data.totpEnabled);
      // The server does not always echo the key state: keep ours, then re-read it.
      if ('webauthnEnabled' in data) setWebauthnEnabled(!!data.webauthnEnabled);
      setWebauthnCredentials(Array.isArray(data.credentials) ? data.credentials : []);
      setPreferredMfaMethod(String(data.preferredMfaMethod || 'any'));
      setBootstrapState((prev) => ({
        ...prev,
        totpEnabled: !!data.totpEnabled,
        webauthnEnabled: !!data.webauthnEnabled
      }));
    } catch (_) {}
  };

  useEffect(() => {
    if (auth.token) onLoad2FAStatus();
  }, [auth.token]);

  const onRegisterPasskey = async (label = '') => {
    setTotpError('');
    setWebauthnBusy(true);
    try {
      const options = await beginWebAuthnRegistration({ label });
      const registration = await createBrowserPasskey(options);
      const data = await verifyWebAuthnRegistration({
        requestId: options.requestId,
        label,
        ...registration
      });
      // The server does not always echo the key state: keep ours, then re-read it.
      if ('webauthnEnabled' in data) setWebauthnEnabled(!!data.webauthnEnabled);
      setTotpEnabled(!!data.totpEnabled);
      if (data.preferredMfaMethod) setPreferredMfaMethod(String(data.preferredMfaMethod));
      await onLoad2FAStatus();
      const bootstrap = data.bootstrap || {};
      setBootstrapState({
        required: !!bootstrap.required,
        passwordChangeRequired: !!bootstrap.passwordChangeRequired,
        mfaSetupRequired: !!bootstrap.mfaSetupRequired,
        totpEnabled: !!data.totpEnabled,
        webauthnEnabled: !!data.webauthnEnabled
      });
      setWebauthnLabel('');
    } catch (error) {
      const message = error.message || t('feedback.failedRegisterPasskey');
      if (message.toLowerCase().includes('valid domain')) {
        setTotpError(`${message} ${t('feedback.currentOrigin', { value: window.location.origin })}`);
      } else {
        setTotpError(message);
      }
    } finally {
      setWebauthnBusy(false);
    }
  };

  const onDeletePasskey = async (credentialId) => {
    setTotpError('');
    setWebauthnBusy(true);
    try {
      const data = await deleteWebAuthnCredential(credentialId);
      // The server does not always echo the key state: keep ours, then re-read it.
      if ('webauthnEnabled' in data) setWebauthnEnabled(!!data.webauthnEnabled);
      setTotpEnabled(!!data.totpEnabled);
      setWebauthnCredentials(Array.isArray(data.credentials) ? data.credentials : []);
      if (data.preferredMfaMethod) setPreferredMfaMethod(String(data.preferredMfaMethod));
      setBootstrapState((prev) => ({
        ...prev,
        mfaSetupRequired: !data.totpEnabled && !data.webauthnEnabled,
        totpEnabled: !!data.totpEnabled,
        webauthnEnabled: !!data.webauthnEnabled
      }));
    } catch (error) {
      setTotpError(error.message || t('feedback.failedRemovePasskey'));
    } finally {
      setWebauthnBusy(false);
    }
  };

  const onUpdateMfaPreference = async (method) => {
    setTotpError('');
    try {
      const data = await setMfaPreference(method);
      setPreferredMfaMethod(String(data.preferredMfaMethod || method || 'any'));
    } catch (error) {
      setTotpError(error.message || t('feedback.failedSaveMfaPreference'));
    }
  };

  useEffect(() => {
    if (!auth.token) {
      setBootstrapState({
        required: false,
        passwordChangeRequired: false,
        mfaSetupRequired: false,
        totpEnabled: false,
        webauthnEnabled: false
      });
      setWebauthnEnabled(false);
      setWebauthnCredentials([]);
      return;
    }
    let active = true;
    fetchBootstrapStatus()
      .then((data) => {
        if (!active) return;
        const bootstrap = data.bootstrap || {};
        setBootstrapState({
          required: !!bootstrap.required,
          passwordChangeRequired: !!bootstrap.passwordChangeRequired,
          mfaSetupRequired: !!bootstrap.mfaSetupRequired,
          totpEnabled: !!bootstrap.totpEnabled,
          webauthnEnabled: !!bootstrap.webauthnEnabled
        });
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [auth.token]);

  useEffect(() => {
    let active = true;
    if (!totpSetupData?.otpauthUri) {
      setTotpQrDataUrl('');
      return;
    }
    QRCode.toDataURL(totpSetupData.otpauthUri, {
      errorCorrectionLevel: 'M',
      margin: 1,
      width: 220
    })
      .then((url) => {
        if (active) {
          setTotpQrDataUrl(url);
        }
      })
      .catch(() => {
        if (active) {
          setTotpQrDataUrl('');
        }
      });
    return () => {
      active = false;
    };
  }, [totpSetupData]);


  // ── Recording handlers ──

  // The evidence page loads its own data; callers navigate to /preuves.
  const openRecordings = (sessionId = null) => {
    setEvidenceFocus(sessionId);
  };

  // ── Shadow session handlers ──
  const openShadow = (session) => {
    closeShadow();
    setShadowSession(session);
    setShadowStatus('connecting');

    setTimeout(() => {
      if (!shadowTermRef.current) return;
      const terminal = new Terminal({
        fontFamily: '"IBM Plex Mono", "Fira Code", monospace',
        fontSize: 13,
        cursorBlink: false,
        disableStdin: true,
        theme: {
          background: '#1a0a2e',
          foreground: '#f9fafb',
          cursor: '#f59e0b'
        }
      });
      const fitAddon = new FitAddon();
      terminal.loadAddon(fitAddon);
      terminal.open(shadowTermRef.current);
      fitAddon.fit();
      shadowTermInstanceRef.current = terminal;
      shadowFitRef.current = fitAddon;

      const wsUrl = buildWebSocketUrl('/api/ws/shadow', {
        sessionId: session.id
      });
      const socket = new WebSocket(wsUrl);
      socket.binaryType = 'arraybuffer';
      shadowSocketRef.current = socket;

      socket.addEventListener('open', () => {
        setShadowStatus('live');
        terminal.writeln(`\x1b[33m${t('feedback.shadowConnected', { id: session.id })}\x1b[0m`);
        terminal.writeln('');
      });

      socket.addEventListener('message', (event) => {
        if (typeof event.data === 'string') {
          try {
            const payload = JSON.parse(event.data);
            if (payload.type === 'status') {
              terminal.writeln(`\x1b[36m${t('feedback.shadowInfo', { message: payload.message })}\x1b[0m`);
            }
          } catch (_) {
            terminal.write(event.data);
          }
          return;
        }
        const decoder = new TextDecoder();
        terminal.write(decoder.decode(event.data));
      });

      socket.addEventListener('close', () => { setShadowStatus('closed'); });
      socket.addEventListener('error', () => { setShadowStatus('error'); });
    }, 100);
  };

  const closeShadow = () => {
    if (shadowSocketRef.current) {
      shadowSocketRef.current.close();
      shadowSocketRef.current = null;
    }
    if (shadowTermInstanceRef.current) {
      shadowTermInstanceRef.current.dispose();
      shadowTermInstanceRef.current = null;
      shadowFitRef.current = null;
    }
    setShadowSession(null);
    setShadowStatus('idle');
  };

  const onChangePassword = async (event) => {
    event.preventDefault();
    setChangePwError('');
    setChangePwSuccess('');
    if (changePwNew !== changePwConfirm) {
      setChangePwError(t('feedback.passwordsDoNotMatch'));
      return;
    }
    try {
      const data = await changePassword(changePwCurrent, changePwNew, {
        keepCurrentSession: bootstrapRequired
      });
      setChangePwSuccess(
        bootstrapRequired
          ? t('feedback.passwordUpdatedContinueMfa')
          : t('feedback.passwordChanged')
      );
      setChangePwCurrent('');
      setChangePwNew('');
      setChangePwConfirm('');
      const bootstrap = data.bootstrap || {};
      setBootstrapState({
        required: !!bootstrap.required,
        passwordChangeRequired: !!bootstrap.passwordChangeRequired,
        mfaSetupRequired: !!bootstrap.mfaSetupRequired,
        totpEnabled,
        webauthnEnabled
      });
      if (!bootstrapRequired) {
        setBootstrapState({
          required: false,
          passwordChangeRequired: false,
          mfaSetupRequired: false,
          totpEnabled,
          webauthnEnabled
        });
      }
    } catch (error) {
      setChangePwError(error.message || t('feedback.failedChangePassword'));
    }
  };

  const toggleDarkMode = () => setDarkMode((prev) => !prev);

  const activeSessions = useMemo(
    () => sessions.filter((session) => session.status === 'active'),
    [sessions]
  );

  // Sessions with their EndoriumFort operator resolved (session.user is the target account).
  const sessionsView = useMemo(
    () => withOperators(sessions, accessGrants, auditItems),
    [sessions, accessGrants, auditItems]
  );

  const formatRelativeDate = (value) => {
    const timestamp = Date.parse(value || '');
    if (!timestamp) return value || t('common.notAvailable');
    const diffSec = Math.floor((Date.now() - timestamp) / 1000);
    if (diffSec < 60) return t('time.justNow');
    if (diffSec < 3600) return t('time.minutesAgo', { count: Math.floor(diffSec / 60) });
    if (diffSec < 86400) return t('time.hoursAgo', { count: Math.floor(diffSec / 3600) });
    return t('time.daysAgo', { count: Math.floor(diffSec / 86400) });
  };

  const renderBootstrapOverlay = () => {
    if (!bootstrapRequired) return null;
    return (
      <FirstLoginDialog
        user={auth.user}
        passwordStep={!!bootstrapState.passwordChangeRequired}
        mfaStep={!!bootstrapState.mfaSetupRequired}
        password={{
          current: changePwCurrent,
          setCurrent: setChangePwCurrent,
          next: changePwNew,
          setNext: setChangePwNew,
          confirm: changePwConfirm,
          setConfirm: setChangePwConfirm,
          onSubmit: onChangePassword,
          error: changePwError
        }}
        mfa={{
          error: totpError,
          setupData: totpSetupData,
          qrDataUrl: totpQrDataUrl,
          code: totpSetupCode,
          setCode: setTotpSetupCode,
          onSetupApp: onSetup2FA,
          onVerify: onVerify2FA,
          onCancel: () => { setTotpSetupData(null); setTotpSetupCode(''); },
          onAddKey: () => onRegisterPasskey(t('dlg.first.keyName', { user: auth.user })),
          keyBusy: webauthnBusy,
          keySupported: isWebAuthnSupported()
        }}
        onLogout={onLogout}
      />
    );
  };

  const renderLogin = () => (
    <LoginPage
      auth={auth}
      onAuthChange={onAuthChange}
      onLogin={onLogin}
      onStartSsoLogin={ssoLogin.available ? onStartSsoLogin : undefined}
      onLoginWithPasskey={onLoginWithPasskey}
      onCancelMfa={() => {
        setTwoFARequired(false);
        setTotpCode('');
        setAvailableMfaMethods([]);
        setWebauthnLoginOptions(null);
        setAuthError('');
      }}
      twoFARequired={twoFARequired}
      availableMfaMethods={availableMfaMethods}
      totpCode={totpCode}
      onTotpChange={setTotpCode}
      webauthnBusy={webauthnBusy}
      webauthnLoginOptions={webauthnLoginOptions}
      authError={authError}
      darkMode={darkMode}
      onToggleDarkMode={toggleDarkMode}
      branding={branding}
    />
  );

  // The signed-in person's own second factors (Security and My account).
  const mfaCardProps = {
    isAdmin: auth.role === 'admin',
    totpEnabled: totpEnabled,
    webauthnEnabled: webauthnEnabled,
    preferredMfaMethod: preferredMfaMethod,
    onUpdateMfaPreference: onUpdateMfaPreference,
    totpSetupData: totpSetupData,
    totpQrDataUrl: totpQrDataUrl,
    totpSetupCode: totpSetupCode,
    setTotpSetupCode: setTotpSetupCode,
    onSetup2FA: onSetup2FA,
    onVerify2FA: onVerify2FA,
    onCancelSetup: () => { setTotpSetupData(null); setTotpSetupCode(''); },
    totpError: totpError,
    totpDisableCode: totpDisableCode,
    setTotpDisableCode: setTotpDisableCode,
    onDisable2FA: onDisable2FA,
    webauthnSupported: isWebAuthnSupported(),
    webauthnBusy: webauthnBusy,
    webauthnLabel: webauthnLabel,
    setWebauthnLabel: setWebauthnLabel,
    webauthnCredentials: webauthnCredentials,
    onRegisterPasskey: onRegisterPasskey,
    onDeletePasskey: onDeletePasskey
  };

  const renderAdmin = () => (
    <AdminLayout
      sections={adminNavSections}
      current={adminSection}
      onSelect={(id) => {
        const section = adminSections.find((item) => item.id === id);
        if (section?.locked) {
          openUpsell(section.label, section.requiredTier);
          return;
        }
        setAdminSection(id);
        navigate(`/admin/${id}`);
      }}
      footer={`EndoriumFort ${versionText(t, bastionVersion)} · ${licenseEdition === 'enterprise' ? (licenseStatus?.tier || 'enterprise') : 'community'}`}
    >
      {!canManagePlatform ? (
        <SectionCard title={t('admin.requiredTitle')}>
          <EmptyState title={t('admin.requiredTitle')} message={t('admin.requiredMessage')} />
        </SectionCard>
      ) : adminSection === 'resources' ? (
        <ResourcesAdmin
          resources={resources}
          loading={loadingResources}
          focusId={resourceEditFocus}
          onFocusUsed={() => setResourceEditFocus(null)}
          onResourcesChange={setResources}
          onOpenMap={() => navigate('/carte')}
        />
      ) : adminSection === 'license' ? (
        <LicenseAdmin
          status={licenseStatus}
          version={versionText(t, bastionVersion)}
          usersCount={users.length}
          isUnlocked={premiumUnlocked}
          uploadText={licenseUploadText}
          setUploadText={setLicenseUploadText}
          onApply={onApplyLicense}
          onReload={onReloadLicense}
          busy={licenseBusy}
          message={licenseActionMsg}
        />
      ) : adminSection === 'k8s' && premiumUnlocked('pro') ? (
        <KubernetesPage
          resources={resources}
          currentUser={auth.user}
          onEditResource={(resource) => {
            setResourceEditFocus(resource.id);
            setAdminSection('resources');
            navigate('/admin/resources');
          }}
          onNewResource={() => {
            setResourceEditFocus('new:k8s');
            setAdminSection('resources');
            navigate('/admin/resources');
          }}
        />
      ) : adminSection === 'appearance' && premiumUnlocked('pro') ? (
        <AppearancePage branding={branding} onSaved={setBranding} />
      ) : adminSection === 'enterprise' && premiumUnlocked('enterprise') ? (
        <IntegrationsPage />
      ) : adminSection === 'itdr' && premiumUnlocked('enterprise') ? (
        <ThreatsPage
          onOpenJournal={(username) => {
            setJournalActorFocus(username);
            navigate('/journal');
          }}
        />
      ) : adminSection === 'vault' && premiumUnlocked('enterprise') ? (
        <VaultPage resources={resources} />
      ) : adminSection === 'routing' && relaysLicensed ? (
        <RelaysPage
          resources={resources}
          resolveAgentInstallGuide={resolveAgentInstallGuide}
          onOpenZones={() => navigate('/zones')}
        />
      ) : adminSection === 'jit' && jitLicensed ? (
        <JitPage
          resources={resources}
          sessions={sessionsView}
          accessGrants={accessGrants}
          accessProfiles={accessProfiles}
          setAccessProfiles={setAccessProfiles}
          onTerminate={onTerminate}
          onOpenZones={() => navigate('/zones')}
          onOpenUsers={() => {
            setAdminSection('users');
            navigate('/admin/users');
          }}
        />
      ) : adminSection === 'users' ? (
        <UsersAdmin
          users={users}
          resources={resources}
          auditItems={auditItems}
          accessProfiles={accessProfiles}
          profilesEnabled={jitLicensed}
          roleBlueprints={roleBlueprints}
          currentUser={auth.user}
          loading={loadingUsers}
          onCreate={async (payload) => {
            const created = await createUser(payload);
            setUsers((prev) => [...prev, created]);
            return created;
          }}
          onUpdate={async (userId, payload) => {
            const updated = await updateUser(userId, payload);
            setUsers((prev) => prev.map((item) => (item.id === userId ? updated : item)));
            return updated;
          }}
          onDelete={async (userId) => {
            await deleteUser(userId);
            setUsers((prev) => prev.filter((item) => item.id !== userId));
            return true;
          }}
          onOpenJournal={(username) => {
            setJournalActorFocus(username);
            navigate('/journal');
          }}
        />
      ) : adminSection === 'security' ? (
        <SecurityAdmin
          users={users}
          resources={resources}
          sessions={sessionsView}
          accessRequests={accessRequests}
          stats={stats}
          licenseDaysRemaining={licenseValid ? licenseDaysRemaining : Number.NaN}
          vaultLicensed={premiumUnlocked('enterprise')}
          relaysLicensed={relaysLicensed}
          containment={{
            status: containmentStatus,
            busy: containmentBusy,
            licensed: securityCenterLicensed,
            onToggle: (enabled) => setContainmentEnabled(enabled, enabled ? t('sec.manualReason') : ''),
            onUnlock: () => openUpsell(t('sec.containTitle'), 'enterprise')
          }}
          onGo={(target) => navigate(target)}
        >
          <MfaCard {...mfaCardProps} />
        </SecurityAdmin>
      ) : null}
    </AdminLayout>
  );

  // Security alerts shown above every section (they used to live in the legacy main view).
  const openJournalAt = (sessionId = null) => {
    navigate('/journal');
    openAudit(sessionId);
  };

  const renderGlobalAlerts = () => (
    <>
    {canViewAudit && liveSecurityIncident && (
      <IncidentBanner
        incident={liveSecurityIncident}
        incidentCase={activeSecurityIncident}
        containment={{ enabled: containmentEnabled, updatedBy: containmentStatus.updatedBy }}
        suspects={incidentSuspectSessions}
        activeSuspectCount={activeIncidentSuspectSessions.length}
        strictProfile={liveAlertProfile === 'strict'}
        canManage={canManagePlatform}
        canOperate={canOperateSessions}
        busy={{ case: incidentCaseBusy, containment: containmentBusy }}
        onInvestigate={() => openJournalAt()}
        onOpenSession={(sessionId) => openJournalAt(sessionId)}
        onStrict={() => setLiveAlertProfile('strict')}
        onOpenCase={openIncidentCase}
        onCloseCase={closeIncidentCase}
        onContainment={(enabled) => setContainmentEnabled(enabled)}
        onTerminateSuspects={requestTerminateIncidentSuspects}
        onDismiss={dismissLiveSecurityIncident}
      />
    )}

    {incidentTerminateConfirmOpen && (
      <Dialog
        title={t('live.confirm.title', { count: activeIncidentSuspectSessions.length })}
        onClose={incidentTerminateBusy ? undefined : () => setIncidentTerminateConfirmOpen(false)}
        width={420}
        footer={
          <>
            <span className="ef-dlg__spacer" />
            <button type="button" className="ef-btn" onClick={() => setIncidentTerminateConfirmOpen(false)} disabled={incidentTerminateBusy}>
              {t('common.cancel')}
            </button>
            <button type="button" className="ef-btn ef-btn--primary" onClick={confirmTerminateIncidentSuspects} disabled={incidentTerminateBusy}>
              {incidentTerminateBusy ? t('live.confirm.busy') : t('live.confirm.action', { count: activeIncidentSuspectSessions.length })}
            </button>
          </>
        }
      >
        <p style={{ margin: 0 }}>{t('app.confirmTerminateBody', { count: activeIncidentSuspectSessions.length })}</p>
      </Dialog>
    )}

    {canViewAudit && (
      <LiveAlerts
        alerts={liveSecurityAlerts}
        onDismiss={dismissLiveSecurityAlert}
        onOpenJournal={openJournalAt}
      />
    )}
    </>
  );

  // Modals and viewers opened by session actions, available from every section.
  const renderSessionOverlays = () => (
    <>
    {vncViewerSession && (
      <VncViewerModal
        session={{ ...vncViewerSession, resourceName: resources.find((r) => Number(r.id) === Number(vncViewerSession.resourceId))?.name }}
        onClose={() => setVncViewerSession(null)}
      />
    )}

    {rbiViewerSession && (
      <RbiViewerModal
        session={{ ...rbiViewerSession, resourceName: resources.find((r) => Number(r.id) === Number(rbiViewerSession.resourceId))?.name }}
        onClose={() => {
          const closed = rbiViewerSession;
          setRbiViewerSession(null);
          if (closed?.id) {
            terminateSession(closed.id).catch(() => {});
            setSessions((prev) =>
              prev.map((s) => (s.id === closed.id ? { ...s, status: 'terminated' } : s))
            );
          }
        }}
      />
    )}

    {accessPromptResource && (() => {
      const risk = String(accessPromptResource.riskLevel || '').toLowerCase();
      const highRisk = risk === 'high' || risk === 'critical';
      const setters = {
        reason: setAccessPromptReason,
        ticket: setAccessPromptTicketId,
        purpose: setAccessPromptPurpose,
        evidence: setAccessPromptPurposeEvidence
      };
      return (
        <AccessDialog
          resource={accessPromptResource}
          mode={accessPromptMode}
          containment={{ enabled: containmentEnabled, reason: containmentStatus.reason }}
          values={{
            reason: accessPromptReason,
            ticket: accessPromptTicketId,
            purpose: accessPromptPurpose,
            evidence: accessPromptPurposeEvidence
          }}
          setValue={(key, value) => setters[key](value)}
          required={{
            reason: !!(accessPromptMode === 'request' || accessPromptResource.requireAccessJustification || containmentEnabled || riskPreview?.justificationRequired),
            ticket: !!(riskPreview?.ticketRequired || (accessPromptResource.adaptiveAccessPolicy && highRisk)),
            purpose: highRisk || !!riskPreview?.purposeRequired
          }}
          preview={jitLicensed ? { loading: riskPreviewLoading, error: riskPreviewError, data: riskPreview } : null}
          playbook={{
            current: currentAccessPlaybook,
            onApply: applyCurrentAccessPlaybook,
            onSave: saveCurrentAccessPlaybook,
            onDelete: deleteCurrentAccessPlaybook
          }}
          error={sessionError}
          approvedRequestId={accessPromptRequestId}
          onSubmit={onSubmitAccessPrompt}
          onClose={closeAccessPrompt}
        />
      );
    })()}

    {agentModal && (
      <AgentDialog
        modal={agentModal}
        onLaunch={launchAgentDeepLink}
        onNewPort={async () => {
          const randomPort = 10000 + Math.floor(Math.random() * 50000);
          try {
            const launchPayload = await buildAgentLaunchPayload(agentModal.resource, randomPort, agentModal.sessionId);
            setAgentModal((prev) => (prev ? { ...prev, port: randomPort, launchState: 'idle', ...launchPayload } : prev));
          } catch (error) {
            // The session may have ended: a new connection must go through the access rules again.
            setSessionError(error.message || t('feedback.agentTokenUnavailable'));
          }
        }}
        onClose={() => {
          clearAgentLaunchWatcher();
          setAgentModal(null);
        }}
      />
    )}
    </>
  );

  // ── License banner (Enterprise edition only) ──────────────────────────────
  const renderLicenseBanner = () => {
    if (!auth.token || licenseEdition !== 'enterprise') return null;
    const blocked = licenseState === 'expired' || licenseState === 'revoked';
    const expiring = licenseValid && Number.isFinite(licenseDaysRemaining) && licenseDaysRemaining >= 0 &&
      licenseDaysRemaining <= 7 && !licenseBannerDismissed;
    if (!blocked && !expiring) return null;
    return (
      <LicenseBar
        state={licenseState}
        daysRemaining={licenseDaysRemaining}
        canManage={canManagePlatform}
        onOpenLicense={() => navigate('/admin/license')}
        onDismiss={() => setLicenseBannerDismissed(true)}
      />
    );
  };

  // ── Premium upsell modal (403 license-required or locked tab/section) ──────
  const renderLicenseUpsell = () => {
    if (!licenseUpsell) return null;
    return (
      <UpsellDialog
        feature={licenseUpsell.feature}
        requiredTier={licenseUpsell.requiredTier}
        community={licenseEdition !== 'enterprise'}
        canManage={canManagePlatform}
        onOpenLicense={() => { setLicenseUpsell(null); navigate('/admin/license'); }}
        onClose={() => setLicenseUpsell(null)}
      />
    );
  };

  if (route === '/login') {
    return renderLogin();
  }

  const currentTab = route.startsWith('/compte') ? 'compte' : tabForPath(route)?.id || 'carte';
  let shellBody;
  if (currentTab === 'compte') {
    shellBody = (
      <AccountPage
        user={auth.user}
        roleName={roleName}
        auditItems={auditItems}
        mfa={mfaCardProps}
        password={{
          current: changePwCurrent,
          setCurrent: setChangePwCurrent,
          next: changePwNew,
          setNext: setChangePwNew,
          confirm: changePwConfirm,
          setConfirm: setChangePwConfirm,
          onSubmit: onChangePassword,
          error: changePwError,
          success: changePwSuccess
        }}
        darkMode={darkMode}
        onSetDarkMode={setDarkMode}
        alertProfile={liveAlertProfile}
        onSetAlertProfile={setLiveAlertProfile}
        showAlerts={canViewAudit}
      />
    );
  } else if (currentTab === 'admin') {
    shellBody = renderAdmin();
  } else if (currentTab === 'zones') {
    shellBody = (
      <ZonesPage
        resources={resources}
        policiesLicensed={jitLicensed}
        relaysLicensed={relaysLicensed}
        onResourcesChanged={async () => {
          try {
            const data = await fetchResources();
            setResources(Array.isArray(data.items) ? data.items : []);
          } catch (_) {
            // The next reload will catch up.
          }
        }}
        onEditResource={(resource) => {
          setResourceEditFocus(resource.id);
          setAdminSection('resources');
          navigate('/admin/resources');
        }}
        onUnlock={(feature, tier) => openUpsell(feature, tier)}
      />
    );
  } else if (currentTab === 'carte') {
    // First steps of a new bastion, for administrators, once the data they
    // depend on has loaded (so nothing flashes as "to do" while loading).
    const startReady = canManagePlatform && stats && !loadingUsers && !loadingResources;
    const openAdmin = (section) => {
      setAdminSection(section);
      navigate(`/admin/${section}`);
    };
    const startSteps = !startReady ? [] : [
      // Required in the Enterprise build (premium features stay locked without
      // it), optional in Community (it is how one moves to a paid edition).
      {
        id: 'license',
        done: licenseValid,
        optional: licenseEdition !== 'enterprise',
        onGo: () => openAdmin('license')
      },
      {
        id: 'resource',
        done: resources.length > 0,
        onGo: () => { setResourceEditFocus('new'); openAdmin('resources'); }
      },
      {
        id: 'mfa',
        done: (Number(stats?.users?.adminsWithoutMfa) || 0) === 0,
        onGo: () => openAdmin('security')
      },
      {
        id: 'operator',
        done: users.some((user) => normalizeRole(user.role) !== 'admin'),
        onGo: () => openAdmin('users')
      }
    ];
    shellBody = (
      <MapPage
        intro={startSteps.length ? <GettingStarted user={auth.user} steps={startSteps} /> : null}
        resources={resources}
        sessions={sessionsView}
        auditItems={auditItems}
        currentUser={auth.user}
        canManage={canManagePlatform}
        canViewAudit={canViewAudit}
        relaysEnabled={relaysLicensed}
        onUnlockRelays={() => openUpsell(t('relayLock.label'), 'pro')}
        previewAccess={jitLicensed ? previewSessionRisk : null}
        loading={loadingResources}
        error={resourceError}
        onConnect={(resource) => {
          // The access prompt, terminal and web viewer still live in the Sessions screen.
          navigate('/sessions');
          onConnectResource(resource);
        }}
        onOpenSession={(session) => {
          navigate('/sessions');
          resumeSession(session);
        }}
        onEdit={(resource) => {
          setResourceEditFocus(resource.id);
          setAdminSection('resources');
          navigate('/admin/resources');
        }}
        onAddResource={() => {
          setResourceEditFocus('new');
          setAdminSection('resources');
          navigate('/admin/resources');
        }}
      />
    );
  } else if (currentTab === 'preuves') {
    shellBody = (
      <EvidencePage
        sessions={sessionsView}
        resources={resources}
        recordingsLicensed={premiumUnlocked('pro')}
        evidenceLicensed={premiumUnlocked('enterprise')}
        focusSessionId={evidenceFocus}
        onUnlock={(feature, tier) => openUpsell(feature, tier)}
        onOpenJournal={(sessionId) => {
          navigate('/journal');
          openAudit(sessionId);
        }}
      />
    );
  } else if (currentTab === 'journal') {
    shellBody = (
      <JournalPage
        resources={resources}
        sessionFilter={auditFilter}
        actorFocus={journalActorFocus}
        onActorFocusUsed={() => setJournalActorFocus(null)}
        canViewRecordings={canViewRecordings}
        onRefresh={loadAudit}
        onClearSessionFilter={() => setAuditFilter(null)}
        onFilterSession={(sessionId) => setAuditFilter(sessionId)}
        onOpenRecordings={(sessionId) => {
          navigate('/preuves');
          openRecordings(sessionId);
        }}
      />
    );
  } else if (currentTab === 'demandes') {
    shellBody = (
      <RequestsPage
        requests={accessRequests}
        resources={resources}
        sessions={sessionsView}
        currentUser={auth.user}
        canReview={canManagePlatform}
        licensed={jitLicensed}
        loading={loadingAccessRequests}
        error={accessRequestError}
        onRefresh={reloadAccessRequests}
        onApprove={onApproveAccessRequest}
        onDeny={onDenyAccessRequest}
        onConnect={(resource) => {
          navigate('/sessions');
          onConnectResource(resource);
        }}
        onOpenSession={(session) => {
          navigate('/sessions');
          resumeSession(session);
        }}
        onOpenMap={() => navigate('/carte')}
        onUnlock={() => openUpsell(t('req.title'), 'pro')}
      />
    );
  } else if (currentTab === 'sessions') {
    shellBody = (
      <SessionsPage
        sessions={sessionsView}
        resources={resources}
        currentUser={auth.user}
        canOperate={canOperateSessions}
        canViewAudit={canViewAudit}
        dnaEnabled={premiumUnlocked('enterprise')}
        relayHints={sessionRelayHints}
        relaysEnabled={relaysLicensed}
        onUnlockRelays={() => openUpsell(t('relayLock.label'), 'pro')}
        auditItems={auditItems}
        loading={loadingSessions}
        error={sessionError}
        terminalHost={terminalRef.current}
        activeTerminalSession={activeTerminalSession}
        terminalStatus={terminalStatus}
        terminalError={terminalError}
        terminalInfo={terminalInfo}
        sshPassword={sshPassword}
        onSshPasswordChange={setSshPassword}
        onConnectTerminal={connectTerminal}
        onOpenTerminal={openTerminal}
        onRefitTerminal={refitTerminal}
        snippets={sshSnippetLibrary}
        snippetLabel={snippetLabel}
        snippetCommand={snippetCommand}
        onSnippetLabelChange={setSnippetLabel}
        onSnippetCommandChange={setSnippetCommand}
        onSendSnippet={sendSnippetToTerminal}
        onAddSnippet={addCustomSnippet}
        onRemoveSnippet={removeCustomSnippet}
        shadowSession={shadowSession ? sessionsView.find((s) => s.id === shadowSession.id) || shadowSession : null}
        shadowStatus={shadowStatus}
        shadowTermRef={shadowTermRef}
        onObserve={openShadow}
        onCloseShadow={closeShadow}
        onOpenVnc={openLiveSession}
        onTerminate={onTerminate}
        onOpenAudit={(sessionId) => {
          navigate('/journal');
          openAudit(sessionId);
        }}
        onOpenRecordings={(sessionId) => {
          navigate('/preuves');
          openRecordings(sessionId);
        }}
        onNewSession={() => navigate('/carte')}
      />
    );
  }

  return (
    <>
      {renderLicenseBanner()}
      <AppShell
        route={route}
        version={versionText(t, bastionVersion)}
        onNavigate={navigate}
        visibleTabs={visibleShellTabs}
        counts={{
          sessions: activeSessions.length,
          demandes: canManagePlatform
            ? accessRequests.filter((item) => item.status === 'pending').length
            : 0
        }}
        user={auth.user}
        roleName={roleName}
        sessions={sessionsView}
        onOpenSession={(session) => {
          navigate('/sessions');
          resumeSession(session);
        }}
        onTerminateSession={onTerminate}
        darkMode={darkMode}
        onToggleDarkMode={toggleDarkMode}
        onOpenAccount={() => navigate('/compte')}
        onLogout={onLogout}
      >
        <div className="ef-legacy">
          {renderGlobalAlerts()}
          {shellBody}
        </div>
      </AppShell>
      {renderSessionOverlays()}
      {renderLicenseUpsell()}
      {renderBootstrapOverlay()}
    </>
  );
}
