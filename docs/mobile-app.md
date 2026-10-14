# EndoriumFort — Application mobile (Android + iOS)

**Écrit pour** : l'équipe de développement (décisions, architecture, état du backend, suite).
**Dernière mise à jour** : 2026-10-09 · **État** : backend MVP terminé ; app non démarrée.

---

## 1. Vision & périmètre

Un bastion PAM, c'est du SSH/RDP/navigateur isolé — **inadapté à un petit écran**. L'app mobile ne clone **pas** le desktop. Son usage à forte valeur, façon Duo / Okta Verify / 1Password :

**Cœur (MVP) :**
1. **Approbation d'accès JIT en push** — une demande d'accès arrive → notification → l'admin approuve/refuse d'un geste + biométrie, avec **signature cryptographique** non-répudiable.
2. **Authentificateur MFA** — TOTP intégré **et** passkey/WebAuthn (biométrie comme second facteur).

**Plus tard :** validation de connexion en push, alertes Security Center, consultation audit/sessions + kill de session à distance.

**Hors périmètre mobile :** SSH/RDP/RBI complets (UX intenable) ; éventuel terminal SSH léger en v2.

---

## 2. Décisions validées

| Sujet | Décision | Raison |
|---|---|---|
| **Stack** | **React Native + Expo** | Réutilise l'expertise React 19 du frontend ; écosystème mature (passkeys, biométrie, push) |
| **Build** | **Expo Dev Client / EAS Build** (pas Expo Go) | passkeys, cert pinning et UnifiedPush exigent des modules natifs |
| **Push** | **Hybride** : FCM/APNs par défaut + UnifiedPush/ntfy auto-hébergé + fallback polling | Souveraineté/air-gap : certains clients refusent le cloud Google/Apple |
| **MVP** | Authentificateur (TOTP/passkey) + approbations JIT en push | ~80 % de la valeur |
| **Open-core** | L'app vit dans `mobile/` du dépôt **CE public** (c'est un client, comme l'agent Go) | Le premium est gaté **côté serveur** ; l'authentificateur marche en CE |

---

## 3. Architecture

```
┌─ App RN/Expo ─────────────┐     HTTPS (cert pinning)      ┌─ Bastion (C++/Crow) ─┐
│ Authentificateur (TOTP/   │ ──── REST /api/* ───────────► │ API existante         │
│   passkey) · Approbations │ ◄─── push (« ouvre l'app ») ─ │ + /api/devices        │
│ SecureStore · Biométrie   │                               │ + push dispatch (EE)  │
│ Clé Secure Enclave        │ ──── approbation signée ────► │ + verify signature    │
└───────────────────────────┘                               └───────────────────────┘
   FCM/APNs (défaut) │ UnifiedPush/ntfy (souverain) │ polling (air-gap)
```

L'app est **un client de plus** de l'API REST + WS existante. Le payload push ne contient **jamais** de secret : juste « ouvre l'app » ; les détails sont tirés via l'API authentifiée.

---

## 4. Backend — MVP TERMINÉ

> Tous les fichiers backend ci-dessous sont **non-committés** (à intégrer dans une Release). Build **EE 10/10 + CE 6/6**, chemins crypto testés unitairement.

### 4.1 Enregistrement de device (CE — cœur)

Table `user_devices(id, user_id, platform, label, push_provider, push_token, public_key, created_at, last_seen_at)`, `UNIQUE(user_id, push_token)`.

| Endpoint | Corps / effet |
|---|---|
| `POST /api/devices/register` | `{platform: ios\|android, label?, pushProvider: fcm\|apns\|unifiedpush\|none, pushToken, publicKey?}` → `{status, id}`. UPSERT sur (user, token). Audit `device.register`. |
| `GET /api/devices` | Liste **du caller** (sans exposer les push tokens). |
| `DELETE /api/devices/<id>` | Supprime, **scopé au propriétaire**. Audit `device.delete`. |

Méthodes : `AppContext::register_user_device / list_user_devices / delete_user_device`.
Fichiers : `models.h` (`UserDevice`), `app_context.{h,cc}`, `routes.{h,cc}` (`register_device_routes`), `main.cc`.

> Ces routes passent par le **gate MFA** : l'app doit d'abord enrôler la MFA, puis enregistrer le device.

### 4.2 Push à la création d'une demande d'accès (EE)

- Seam `AppContext::on_access_request_created(const AccessRequest&)` — no-op en CE / sans module ; invoqué dans `pro/access_governance.cc` après l'audit de création.
- Module `pro/push.cc` (`register_push`, câblé dans `register_pro_features`) :
  - **Destinataires** = admins (snapshot sous `user_mutex`, envoi sur **thread détaché** → l'API n'est pas bloquée).
  - **Routage par provider** (par device) :
    - `unifiedpush` / `ntfy` / `webhook` → **POST direct** sur l'URL d'endpoint du device (souverain)
    - `fcm` / `apns` → POST vers `ENDORIUMFORT_PUSH_RELAY_URL` (+ `ENDORIUMFORT_PUSH_RELAY_AUTH` optionnel) → les secrets Google/Apple restent **hors** du bastion
    - `none` → loggé
  - Réutilise le client sortant `http_proxy_request`. Payload sans secret (`{title, body, data:{type, id}}`).
  - Audit : `push.sent | push.failed | push.skipped | push.logged`.

### 4.3 Approbation signée (EE)

- `AppContext::verify_device_signature(user_id, device_id, message, signature_b64url)` — clé publique SPKI du device (scopée au propriétaire) + `d2i_PUBKEY` + `EVP_DigestVerify` (**ES256**/EC-P256 via SHA-256 ; Ed25519 via md null). Réutilise le socle de vérif WebAuthn/licences.
- `POST /api/access-requests/<id>/approve` et `/deny` (pro) :
  1. **Garde `pending`** : requête déjà décidée → `409` (⇒ approbation signée **mono-usage**).
  2. Corps optionnel `{deviceId, signature}` → vérifie la signature sur le message canonique **`"<approve|deny>:<reqId>:<createdAt>"`** (deux phases : lecture d'état → vérif hors verrou → re-check sous verrou → commit, anti-TOCTOU).
  3. Audit `access_request.approve|deny` avec `"signed": true|false`.
- L'approbation **web par session** reste inchangée si aucune signature n'est envoyée.

### 4.4 Déjà présent et réutilisé
- Enrôlement **TOTP** (`/api/auth/setup-2fa`, `verify-2fa`) et **WebAuthn** (`/api/auth/webauthn/register/*`).
- `GET /api/access-requests` (liste des demandes en attente).

### 4.5 Variables d'environnement (nouvelles)
| Variable | Rôle |
|---|---|
| `ENDORIUMFORT_PUSH_RELAY_URL` | Relais pour FCM/APNs (garde les creds Google/Apple hors du bastion) |
| `ENDORIUMFORT_PUSH_RELAY_AUTH` | Jeton Bearer optionnel pour le relais |

### 4.6 Événements d'audit ajoutés
`device.register`, `device.delete`, `push.sent`, `push.failed`, `push.skipped`, `push.logged`, + champ `signed` sur `access_request.approve|deny`.

### 4.7 Fichiers backend touchés (non-committés)
`backend/src/models.h`, `backend/src/app_context.{h,cc}`, `backend/src/routes.{h,cc}`, `backend/src/main.cc`, `backend/src/pro/{access_governance.cc,push.cc,pro_features.cc}`, `backend/CMakeLists.txt`, `backend/tests/device_test.cc`.

---

## 5. Modèle de sécurité (app — à respecter)

- Token en **Keychain (iOS) / Keystore (Android)**, jamais en clair.
- **Déverrouillage biométrique** à l'ouverture + **ré-auth avant chaque approbation**.
- **Cert pinning** vers le bastion (même principe que `agent/tlspin.go`).
- **Keypair device en Secure Enclave / StrongBox** (EC P-256 / ES256) → signe les approbations ; la clé publique SPKI est envoyée à `/api/devices/register` en base64url.
- **Message signé** : exactement `"<approve|deny>:<reqId>:<createdAt>"` (valeurs issues de `GET /api/access-requests`). Signature DER ECDSA → base64url dans le corps de `approve`/`deny`.
- Anti-root/jailbreak, blocage des captures d'écran sur écrans sensibles, zéro secret en log/cache.
- **Appairage initial par QR code** (URL bastion + empreinte du certificat) scanné depuis l'admin web.

---

## 6. Reste à faire — l'app Expo

Nouvel écosystème (Node/Expo/EAS, build natif) → grosse arborescence `mobile/`.

**Structure cible :**
```
mobile/
├── app/                      # expo-router
│   ├── onboarding/           # appairage QR (URL + pinning)
│   ├── authenticator/        # TOTP + passkey
│   ├── approvals/            # demandes en attente → approuver/refuser (signé)
│   └── settings/             # devices, biométrie
├── lib/
│   ├── api.ts                # client REST (token, pinning)
│   ├── crypto.ts             # keypair device, signature du défi
│   ├── push/                 # fcm | apns | unifiedpush | polling
│   ├── secure.ts             # SecureStore
│   └── biometric.ts
└── app.config.ts
```

**Librairies clés :** `expo-secure-store`, `expo-local-authentication`, `expo-notifications`, `react-native-passkeys`, `otplib`, `@tanstack/react-query`, cert pinning via config plugin.

**Phases :**
1. **MVP** : appairage QR + pinning + biométrie + authentificateur TOTP/passkey + approbations push (FCM/APNs).
2. UnifiedPush/air-gap, alertes Security Center, sessions actives + kill à distance.
3. Audit mobile, terminal SSH léger (optionnel).

---

## 7. Récap conformité/qualité
- Backend : **EE 10/10, CE 6/6** ; parseur d'URL push et vérif ES256 testés.
- Souveraineté préservée (push hybride, secrets provider hors bastion).
- Cohérent open-core : app = client CE, premium gaté serveur.

*Document interne — tenir à jour au fil de l'avancement de l'app.*
