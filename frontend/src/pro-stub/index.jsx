// EndoriumFort — Community Edition stub for the `@pro` overlay.
//
// The premium UI is physically absent from the Community build; the `@pro` Vite
// alias resolves here (src/pro/ is not shipped in the public core). These no-op
// components keep imports valid. Premium tabs/sections are already gated in
// App.jsx (locked → upsell modal), so in CE these never actually render — and
// their heavy dependencies (e.g. @novnc) never enter the CE bundle.
export function RecordingsPanel() {
  return null;
}

export function VncViewerModal() {
  return null;
}

export function EnterpriseIamPanel() {
  return null;
}

export function RelayControlPanel() {
  return null;
}

export function JitGovernancePanel() {
  return null;
}

export const proEdition = 'community';
