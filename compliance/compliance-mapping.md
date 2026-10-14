# EndoriumFort — Matrice de conformité des contrôles techniques

**Destiné à** : un auditeur externe / responsable conformité évaluant EndoriumFort (bastion PAM auto‑hébergé).
**Date** : 2026‑10‑09 · **Édition** : Community (CE) + Enterprise (EE) · **Statut** : document de travail interne (non publié).

---

## 1. Objet et périmètre

Ce document met en correspondance les **contrôles techniques** implémentés dans le produit avec les exigences d'**ANSSI** (hygiène informatique, PA‑022, recommandations crypto), **ISO/IEC 27001:2022** (Annexe A), **SOC 2** (Trust Services Criteria), **RGPD**, **NIST** (SP 800‑53 rev5 et SP 800‑63B) et **PCI DSS v4.0**.

**Ce document ne couvre que les contrôles réalisables dans le logiciel.** Les référentiels cités exigent aussi des contrôles **organisationnels** (politiques, revues d'accès périodiques, gestion du changement, sensibilisation, continuité) et, pour ISO 27001 / SOC 2 / PCI / CSPN, un **audit par un tiers accrédité**. Ces éléments sont hors du périmètre produit et doivent être traités au niveau de l'organisation exploitante.

**Lecture des statuts** :
- **Implémenté** — présent dans le code, vérifié (build + tests).
- **Configurable** — présent, activé/réglé par variable d'environnement (défaut conforme).
- **Déploiement** — fourni mais activé au niveau infrastructure (image/cluster/volume).
- **Hors périmètre** — exigence organisationnelle ou certification tierce.

---

## 2. Référence de configuration sécurisée (défauts conformes)

L'auditeur vérifie la configuration réellement déployée. Toutes les variables ci‑dessous ont un **défaut conforme**, surchargeable.

| Variable | Défaut | Contrôle |
|---|---|---|
| `ENDORIUMFORT_REQUIRE_MFA` | `all` | MFA obligatoire pour tous les comptes (serveur) |
| `ENDORIUMFORT_IDLE_TIMEOUT_SECONDS` | `900` | Expiration sur inactivité (15 min) |
| `ENDORIUMFORT_TOKEN_TTL_SECONDS` | `3600` | Durée de vie absolue de session (1 h) |
| `ENDORIUMFORT_TUNNEL_CREDENTIAL_TTL_SECONDS` | `43200` | Durée de vie du credential de tunnel, limité à une ressource (12 h) |
| `ENDORIUMFORT_DB_DSN` | *(vide)* | Moteur de stockage : SQLite (fichier) ou PostgreSQL (`postgresql://…`) |
| `ENDORIUMFORT_PASSWORD_MIN_LENGTH` | `12` | Longueur minimale de mot de passe (plancher 8) |
| `ENDORIUMFORT_PASSWORD_HISTORY` | `5` | Non‑réutilisation des N derniers mots de passe |
| `ENDORIUMFORT_AUDIT_HMAC_KEY` | *(vide)* | Clé HMAC de la chaîne d'audit (à stocker hors du volume de données) |
| `ENDORIUMFORT_AUDIT_MAX_FILE_MB` | `0` (off) | Rotation/archivage du journal d'audit |
| `ENDORIUMFORT_AUDIT_RETENTION_DAYS` | `0` (conserver) | Purge des archives d'audit au‑delà de N jours |
| `ENDORIUMFORT_DB_ENCRYPTION_KEY` | *(vide)* | Chiffrement de la base au repos (SQLCipher) |
| `ENDORIUMFORT_DB_ENCRYPTION_MIGRATE` | *(vide)* | Migration en place d'une base existante en clair |
| `ENDORIUMFORT_VAULT_KEY` / `_OLD` | *(vide)* | Clé de chiffrement du coffre (+ rotation sans interruption) |
| `ENDORIUMFORT_BOOTSTRAP_ADMIN_PASSWORD` | *(vide)* | Mot de passe admin initial (sinon aléatoire, imprimé une fois) |

> Le binaire journalise à chaque démarrage un récapitulatif `[config]` reprenant ces valeurs (preuve de configuration).

---

## 3. Matrice de contrôles

### 3.1 Identité & authentification

| Contrôle | Implémentation (preuve) | ANSSI | ISO 27001:2022 | SOC 2 | RGPD | NIST | PCI DSS v4 | Statut |
|---|---|---|---|---|---|---|---|---|
| **MFA obligatoire (TOTP / WebAuthn), imposée côté serveur** | Gate middleware `mfa_enrollment_gate` (app_context.cc) ; `ENDORIUMFORT_REQUIRE_MFA` | Hygiène §… auth forte | A.8.5, A.5.17 | CC6.1, CC6.6 | art.32 | IA‑2, 800‑63B AAL2 | 8.4, 8.5 | **Implémenté** |
| **Secret TOTP issu d'un CSPRNG** (160 bits) | `totp.h generate_secret` → `RAND_bytes` | reco crypto | A.8.24 | CC6.1 | art.32 | SC‑13 | 8.3 | **Implémenté** |
| **Anti‑force brute** (par compte **et** par IP, back‑off exponentiel) | routes.cc `check_rate_limit` / `record_failed_login_attempt` | hygiène | A.8.5 | CC6.1 | — | AC‑7 | 8.3.4 | **Implémenté** |
| **Longueur mot de passe ≥ 12** | `crypto.h validate_password` ; `ENDORIUMFORT_PASSWORD_MIN_LENGTH` | reco mots de passe | A.5.17 | CC6.1 | — | 800‑63B §5.1.1 | 8.3.6 | **Implémenté** |
| **Blocage des mots de passe courants/compromis** | `crypto.h is_common_password` | reco mots de passe | A.5.17 | CC6.1 | — | 800‑63B §5.1.1.2 | 8.3.5 | **Implémenté** |
| **Non‑réutilisation (historique N)** | table `password_history`, `password_was_recently_used` ; `ENDORIUMFORT_PASSWORD_HISTORY` | — | A.5.17 | CC6.1 | — | IA‑5 | 8.3.7 | **Implémenté** |
| **Hachage mot de passe fort (scrypt N=32768)** | `crypto.h hash_password_scrypt` | reco crypto | A.8.24 | CC6.1 | art.32 | IA‑5(1) | 8.3.6 | **Implémenté** |
| **Pas de secret par défaut livré** (admin aléatoire, imprimé 1×) | `app_context.cc seed_default_admin` | hygiène | A.5.17 | CC6.1 | — | IA‑5 | 2.1, 2.2 | **Implémenté** |
| **RBAC + moindre privilège** | `has_permission`, catalogue de permissions | PA‑022 | A.5.15, A.8.2, A.8.3 | CC6.1, CC6.3 | art.32 | AC‑3, AC‑6 | 7.1–7.2 | **Implémenté** |
| **Double validation JIT (dual‑approval)** (EE) | `pro/access_governance.cc` | PA‑022 | A.5.15 | CC6.1 | — | AC‑6(… ) | 7.2 | **Implémenté (EE)** |

### 3.2 Gestion de session

| Contrôle | Implémentation | ANSSI | ISO 27001:2022 | SOC 2 | RGPD | NIST | PCI DSS v4 | Statut |
|---|---|---|---|---|---|---|---|---|
| **Timeout d'inactivité (15 min)** | `validate_and_touch_session` ; `ENDORIUMFORT_IDLE_TIMEOUT_SECONDS` | hygiène | A.8.5 | CC6.1 | — | AC‑11, AC‑12 | 8.2.8 | **Implémenté** |
| **Durée de vie absolue de session** | `compute_expiry` ; `ENDORIUMFORT_TOKEN_TTL_SECONDS` | hygiène | A.8.5 | CC6.1 | — | AC‑12 | 8.2.8 | **Implémenté** |
| **Credential de tunnel à portée restreinte** | `pro/tunnel.cc resolve_tunnel_requester` ; lié à (ressource, IP source, agent) ; révoqué avec le compte ; `ENDORIUMFORT_TUNNEL_CREDENTIAL_TTL_SECONDS` | moindre privilège | A.8.2 | CC6.3 | — | AC‑6, IA‑5 | 7.2 | **Implémenté** |
| **Jetons de session via CSPRNG** | `app_context.cc generate_token` → `RAND_bytes` | reco crypto | A.8.24 | CC6.1 | — | SC‑13 | 6.2 | **Implémenté** |
| **Cookies `HttpOnly; SameSite=Strict; Secure`** | `utils.h build_auth_cookie` | hygiène | A.8.5 | CC6.6 | — | SC‑23 | 6.2 | **Implémenté** |

### 3.3 Cryptographie & secrets

| Contrôle | Implémentation | ANSSI | ISO 27001:2022 | SOC 2 | RGPD | NIST | PCI DSS v4 | Statut |
|---|---|---|---|---|---|---|---|---|
| **TLS 1.2/1.3, chiffrements AEAD + PFS** | docker/nginx.conf | reco crypto (B1) | A.8.24 | CC6.7 | art.32 | SC‑8 | 4.2.1 | **Implémenté** |
| **Primitives via OpenSSL** (aucune crypto maison) | crypto.h, totp.h (`EVP_*`, `RAND_bytes`, `CRYPTO_memcmp`) | reco crypto | A.8.24 | CC6.1 | art.32 | SC‑13 | 6.2 | **Implémenté** |
| **Coffre AES‑256‑GCM (IV via CSPRNG)** | `crypto.h aes256_encrypt` | reco crypto | A.8.24 | C1.1 | art.32 | SC‑28 | 3.5 | **Implémenté** |
| **Rotation de la clé de coffre (sans interruption)** | `get_vault_keys` (primaire + anciennes) ; `ENDORIUMFORT_VAULT_KEY_OLD` | reco crypto | A.8.24 | CC6.1 | — | SC‑12 | 3.6, 3.7 | **Configurable** |
| **Chiffrement de la base au repos** | SQLCipher (database.h `PRAGMA key`, fail‑closed) ; `ENDORIUMFORT_DB_ENCRYPTION_KEY` | reco crypto | A.8.24 | C1.1 | art.32 | SC‑28 | 3.5 | **Configurable** |
| **Licences : signature hybride Ed25519 + ML‑DSA‑65 (PQC)** | license.h (`EVP_DigestVerify`) | reco crypto / PQC | A.8.24 | CC6.1 | — | — | — | **Implémenté** |

### 3.4 Journalisation & imputabilité

| Contrôle | Implémentation | ANSSI | ISO 27001:2022 | SOC 2 | RGPD | NIST | PCI DSS v4 | Statut |
|---|---|---|---|---|---|---|---|---|
| **Couverture d'événements** (login succès/échec, logout, MFA, CRUD users, mdp, sessions, accès) | `append_audit` (types d'événements) | hygiène | A.8.15 | CC7.2 | art.30, art.32 | AU‑2, AU‑3 | 10.2 | **Implémenté** |
| **Journal d'audit infalsifiable (chaîne HMAC/SHA‑256)** | `append_audit` + `verify_audit_chain` ; `GET /api/audit/verify` | hygiène | A.8.15 | CC7.2, CC7.3 | art.32 | AU‑9 | 10.3.4, 10.5 | **Implémenté** |
| **Chaîne de hachage par session (Session DNA)** (EE) | `append_session_dna_entry` (SQLite `session_dna_chain`) | — | A.8.15 | CC7.2 | — | AU‑10 | 10.3 | **Implémenté (EE)** |
| **Rétention / rotation des journaux** | `maybe_rotate_audit_locked` ; `ENDORIUMFORT_AUDIT_MAX_FILE_MB` / `_RETENTION_DAYS` | hygiène | A.8.15 | CC7.2 | art.5(1)(e) | AU‑4, AU‑11 | 10.7 | **Configurable** |
| **Horodatage fiable (NTP)** | Responsabilité de l'hôte / conteneur | hygiène | A.8.15 | CC7.2 | — | AU‑8 | 10.6 | **Hors périmètre** |

### 3.5 Protection des données & vie privée (RGPD)

| Contrôle | Implémentation | ANSSI | ISO 27001:2022 | SOC 2 | RGPD | NIST | PCI DSS v4 | Statut |
|---|---|---|---|---|---|---|---|---|
| **Droit d'accès / portabilité** (export des données d'une personne) | `GET /api/users/<id>/data-export` | — | A.5.34 | P (privacy) | art.15, art.20 | — | — | **Implémenté** |
| **Droit à l'effacement** (suppression compte + WebAuthn + historique mdp) | `delete_user_db` | — | A.8.10 | P | art.17 | — | — | **Implémenté** |
| **Rétention d'audit sous base légale** (le journal chaîné n'est pas réécrit à l'effacement) | append‑only + §3.4 | — | A.5.34, A.8.15 | P | art.17(3), art.5 | — | — | **Implémenté / décision documentée (§4)** |
| **Chiffrement des données au repos** | §3.3 (SQLCipher + coffre) | reco crypto | A.8.24 | C1.1 | art.32 | SC‑28 | 3.5 | **Configurable** |

### 3.6 Durcissement réseau, conteneur & surface

| Contrôle | Implémentation | ANSSI | ISO 27001:2022 | SOC 2 | RGPD | NIST | PCI DSS v4 | Statut |
|---|---|---|---|---|---|---|---|---|
| **En‑têtes de sécurité** (CSP, HSTS, X‑Frame‑Options, COOP/CORP, Referrer‑Policy, Permissions‑Policy) | security_middleware.h | hygiène | A.8.9 | CC6.6 | — | SC‑7 | 6.4.2 | **Implémenté** |
| **Backend non‑root** | Dockerfile `gosu` + entrypoint.sh | hygiène | A.8.9 | CC6.1 | — | CM‑7, AC‑6 | 2.2 | **Implémenté** |
| **Durcissement nginx** (`server_tokens off`, ciphers forts, OCSP) | docker/nginx.conf | hygiène | A.8.9 | CC6.6 | — | SC‑7 | 2.2 | **Implémenté** |
| **Protection SSRF** (plages numériques via `inet_pton`) | `AppContext::is_safe_target` | hygiène | A.8.9 | CC6.6 | — | SC‑7 | 6.2 | **Implémenté** |
| **Scan de vulnérabilités en CI (Trivy)** | .github/workflows/security-scan.yml | hygiène | A.8.8 | CC7.1 | — | RA‑5 | 6.3, 11.3 | **Implémenté** |
| **Triage des vulnérabilités documenté** | .snyk, .trivyignore (justifications + expiration) | — | A.8.8 | CC7.1 | — | RA‑5 | 6.3 | **Implémenté** |

---

## 4. Conflits de normes & décisions

- **Rétention des journaux** : PCI DSS 10.7 impose ≥ 12 mois ; le RGPD (art. 5(1)(e)) impose la minimisation. → **Rendu configurable** (`ENDORIUMFORT_AUDIT_RETENTION_DAYS`) ; l'exploitant fixe sa politique selon son contexte (par défaut : conservation illimitée, à restreindre).
- **Expiration périodique des mots de passe** : NIST 800‑63B **déconseille** la rotation forcée ; PCI v4 est passé à une approche par le risque. → **Pas d'expiration forcée** ; renforcement par longueur (12), blocklist et historique de non‑réutilisation.
- **Composition des mots de passe** : NIST déconseille les règles de composition ; PCI 8.3.6 exige alphanumérique. → Règle alphanumérique conservée (sur‑ensemble conforme PCI), couplée à la longueur et à la blocklist.

---

## 5. Points résiduels / hors périmètre produit

| Élément | Référentiel | Nature |
|---|---|---|
| **Module cryptographique validé FIPS 140‑3** | NIST / FedRAMP | Nécessite le provider FIPS d'OpenSSL + build validé — non requis par ANSSI/ISO/RGPD. Activable si FedRAMP visé. |
| **Synchronisation horloge (NTP)** | PCI 10.6, NIST AU‑8 | Responsabilité de l'hôte / orchestrateur. |
| **Politiques & preuves de processus** (revues d'accès, gestion du changement, sensibilisation, PCA/PRA) | ISO 27001 clauses 4–10, SOC 2 CC1–CC5 | Organisationnel. |
| **Audit par tiers accrédité** | ISO 27001, SOC 2, PCI (QSA), CSPN | Externe. |
| **Chiffrement de volume** (défense en profondeur sous la base) | PCI 3.5, HDS | Déploiement (LUKS / StorageClass chiffrée / volume cloud). |

---

## 6. Index des preuves (vérification par l'auditeur)

| Preuve | Méthode |
|---|---|
| Intégrité du journal d'audit | `GET /api/audit/verify` → `{intact, lines, firstBrokenLine, keyed}` |
| Export de données d'une personne (RGPD) | `GET /api/users/<id>/data-export` |
| MFA imposée | Tenter un appel API authentifié sans facteur enrôlé → `403 mfa_enrollment_required` |
| Timeout d'inactivité | Session inactive > 15 min → `401` au prochain appel |
| Politique mot de passe | `POST /api/auth/change-password` avec mot de passe faible/réutilisé → `400` + message |
| Configuration effective | Log de démarrage `[config] …` |
| Chiffrement BDD actif | Démarrage avec clé mais sans SQLCipher → refus explicite (fail‑closed) ; sinon en‑tête de fichier non `SQLite format 3` |
| Rotation clé de coffre | Déchiffrement d'anciennes entrées après bascule `VAULT_KEY` + `VAULT_KEY_OLD` |
| Tests | `ctest` (EE 9/9, CE 5/5) ; vecteurs RFC 6238 (TOTP) |

---

*Document de travail — à relire par un juriste et un auditeur accrédité avant toute communication externe. Les correspondances de clauses sont indicatives et destinées à préparer l'audit, non à en préjuger le résultat.*
