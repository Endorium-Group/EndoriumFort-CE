# Déployer un relais EndoriumFort

**Écrit pour** : l'administrateur du bastion **et** la personne qui héberge le relais.
**Édition** : Enterprise (EE) — le relais nécessite une **licence EE active** sur le bastion.

---

## 1. À quoi sert un relais ?

Par défaut, le bastion se connecte **directement** aux ressources (SSH, RDP, HTTP…). Quand une ressource se trouve sur **un autre réseau** (ex. le LAN d'un ami, un site distant), le bastion n'y a pas accès directement. Un **relais** se déploie **sur ce réseau distant** : il reçoit les connexions du bastion et les réachemine vers les machines locales.

> **Scénario** : ton **bastion** tourne chez toi. Ton ami veut atteindre ses machines (ex. un serveur SSH sur `192.168.1.x`) de **chez lui**. Il déploie un **relais** sur son réseau ; tu rattaches ses ressources à ce relais ; les sessions passent bastion → relais → machine de l'ami.

```
  Toi (bastion)                          Chez l'ami (relais + machines)
┌──────────────┐   mTLS CONNECT    ┌───────────────────────────────┐
│  EndoriumFort │ ───────────────► │ relais :18080  ──► 192.168.1.10:22 (SSH) │
│   (HTTPS)     │ ◄─ heartbeat ─── │ (endoriumfort-relay)           │
└──────────────┘                   └───────────────────────────────┘
```

**Point réseau clé** : le **bastion se connecte AU relais** (le relais écoute, le bastion compose). Le relais, lui, ne fait que des appels **sortants** vers le bastion (enrôlement + heartbeat en HTTPS). Donc :
- Le **bastion** doit être joignable par le relais en **HTTPS** (déjà le cas s'il est publié).
- Le **relais** doit être joignable par le **bastion** sur son **port d'écoute** → **l'ami doit rediriger ce port sur sa box** (port-forwarding).

---

## 2. Prérequis

- Bastion EndoriumFort EE, licence active, accessible en **HTTPS** depuis le réseau de l'ami.
- Binaire relais : `agent/endoriumfort-relay-linux-amd64` (ou buildé depuis `agent/cmd/endoriumfort-relay`). À copier sur une machine **allumée** du réseau de l'ami (peut être une des machines cibles).
- Un compte admin sur le bastion (permission `resources.manage`).

---

## 3. Côté bastion (toi) — préparer l'enrôlement

### 3.1 Activer l'enrôlement des relais
Définis un **secret d'enrôlement** dans l'environnement du bastion, puis redémarre :

```bash
ENDORIUMFORT_RELAY_ENROLL_SECRET="un-secret-long-et-aleatoire"
```
(génère-le avec `openssl rand -hex 32`). Sans ce secret, l'enrôlement est désactivé (`412 Relay enrollment secret is not configured`).

### 3.2 (Si requis) Émettre un certificat relais
Par défaut `ENDORIUMFORT_RELAY_CERT_REQUIRED=true` : chaque relais doit présenter un **certificat applicatif** émis par le bastion.

Via la **console d'admin** (section Relais) ou en API :
```bash
curl -s -X POST https://TON-BASTION/api/relays/certificate \
  -H "Authorization: Bearer <TON_TOKEN_ADMIN>" \
  -H "Content-Type: application/json" -d '{}'
# → { "certificateId": "...", "certificate": "efrcert_...", "expiresAt": "..." }
```
Note la valeur **`certificate`** (`efrcert_…`). *(Pour un simple lab, tu peux poser `ENDORIUMFORT_RELAY_CERT_REQUIRED=false` et sauter cette étape.)*

### 3.3 Émettre un token d'enrôlement à usage unique (recommandé)
```bash
curl -s -X POST https://TON-BASTION/api/relays/enrollment-token \
  -H "Authorization: Bearer <TON_TOKEN_ADMIN>" \
  -H "Content-Type: application/json" -d '{"ttlSeconds": 600}'
# → { "enrollmentToken": "efenr_...", "expiresAt": "..." }
```
Transmets à l'ami, de façon sûre : l'**URL du bastion**, le **token d'enrôlement** (`efenr_…`), et le **certificat** (`efrcert_…`) si requis. *(Alternative : lui donner directement le `ENDORIUMFORT_RELAY_ENROLL_SECRET` — moins propre, car réutilisable.)*

---

## 4. Côté ami — lancer le relais

### 4.1 Démarrage rapide (lab / test) — sans mTLS, fenêtre limitée
Le plus simple pour valider la chaîne. Autorise un CONNECT **en clair** pour une durée bornée, restreint à l'IP du bastion et aux cibles internes :

```bash
./endoriumfort-relay-linux-amd64 \
  --server https://TON-BASTION \
  --relay-id "maison-ami" \
  --label "Relais de l'ami" \
  --enrollment-token "efenr_..." \
  --certificate "efrcert_..." \
  --listen 0.0.0.0:18080 \
  --allow-http-connect-for 24h \
  --allow-http-client <IP_PUBLIQUE_DE_TON_BASTION> \
  --allow-target 192.168.1.10:22
```
- `--listen 0.0.0.0:18080` : écoute sur toutes les interfaces (indispensable pour être joignable depuis l'extérieur).
- `--allow-target` : **répétable** — liste blanche des machines internes atteignables (ex. `192.168.1.10:22`). Sans elle, rien n'est joignable.
- `--allow-http-client` : **répétable** — IP(s) autorisées à utiliser le CONNECT en clair (mets l'IP publique de ton bastion).

### 4.2 Production — proxy CONNECT en mTLS
Le relais écoute en TLS et n'accepte que les clients présentant un certificat signé par la CA de confiance :

```bash
./endoriumfort-relay-linux-amd64 \
  --server https://TON-BASTION \
  --relay-id "maison-ami" \
  --enrollment-token "efenr_..." \
  --certificate "efrcert_..." \
  --listen 0.0.0.0:18080 \
  --tls-cert relay-server.crt --tls-key relay-server.key \
  --client-ca bastion-client-ca.crt \
  --allow-target 192.168.1.10:22
```
- `--tls-cert` / `--tls-key` : certificat **serveur** du relais (son identité TLS côté proxy).
- `--client-ca` : CA qui **autorise le certificat client du bastion** (seul le bastion muni d'un cert signé par cette CA pourra se connecter). Échange cette CA avec la config de sortie du bastion (console d'admin → Relais).

### 4.3 Redirection de port (sur la box de l'ami) — **l'étape qui bloque le plus souvent**
Pour que ton bastion atteigne le relais, l'ami redirige le port d'écoute vers la machine du relais :
- Règle NAT/port-forwarding : `WAN:18080 → IP_LAN_du_relais:18080` (TCP).
- Idéalement, restreindre la source à l'IP publique de ton bastion (pare-feu de la box).
- IP publique dynamique côté ami ? Utiliser un DynDNS, ou héberger le relais sur un petit VPS joignable qui, lui, atteint le LAN via VPN.

---

## 5. Côté bastion (toi) — rattacher les ressources au relais

1. Crée la ressource normalement (ex. SSH vers `192.168.1.10:22`) — la cible est l'adresse **vue par le relais** (donc l'IP **interne** du LAN de l'ami).
2. Rattache-la au relais, via la console d'admin (Ressource → Relais) ou en API :
```bash
curl -s -X POST https://TON-BASTION/api/relays/assign \
  -H "Authorization: Bearer <TON_TOKEN_ADMIN>" \
  -H "Content-Type: application/json" \
  -d '{"resourceId": 42, "relayId": "maison-ami"}'
```
Pour **détacher** : même appel sans `relayId`.

Désormais, une session vers cette ressource est routée **via le relais** (le bastion le vérifie avec `GET /api/relays/resolve/<resourceId>` → `route: "relay"` quand le relais est **online**).

---

## 6. Vérification

- Console d'admin → **Relais** : le relais `maison-ami` apparaît **online** (heartbeat < 90 s), avec sa `sourceIp` et sa version. En API : `GET /api/relays`.
- `GET /api/relays/resolve/<resourceId>` renvoie `"route":"relay"` et `"status":"online"`.
- Ouvre une session vers la ressource : elle doit aboutir sur la machine interne de l'ami.
- Journal d'audit : `relay.enroll.*`, `relay.assignment.updated`, heartbeats.

---

## 7. Dépannage

| Symptôme | Cause probable / correctif |
|---|---|
| `412 enrollment secret is not configured` | `ENDORIUMFORT_RELAY_ENROLL_SECRET` non défini sur le bastion. |
| `426 Relay transport must be TLS` | L'enrôlement doit se faire en **HTTPS** vers le bastion (pas HTTP). |
| Relais **offline** dans la console | Heartbeat ne part pas : vérifier `--server` (HTTPS joignable), l'horloge, le pare-feu sortant côté ami. |
| Session échoue alors que le relais est online | Le **bastion n'atteint pas le port d'écoute** du relais → vérifier le **port-forwarding** et `--listen 0.0.0.0:…`. |
| Connexion refusée vers la machine cible | La cible n'est pas dans `--allow-target`, ou injoignable depuis le relais. |
| CONNECT en clair refusé | En lab, il faut `--allow-http-connect-for <durée>` **et** l'IP du bastion dans `--allow-http-client`. En prod, utiliser le mTLS (§4.2). |
| TLS client rejeté (prod) | Le cert client du bastion n'est pas signé par la CA passée à `--client-ca`. |

---

## 8. Référence

### Flags du relais (`endoriumfort-relay`)
| Flag | Rôle |
|---|---|
| `--server` | URL HTTPS du bastion |
| `--relay-id` | Identifiant unique du relais (**requis**) |
| `--label` | Nom lisible (défaut = relay-id) |
| `--listen` | Adresse d'écoute du proxy CONNECT (défaut `127.0.0.1:18080` ; mettre `0.0.0.0:…`) |
| `--enroll-secret` / `--enrollment-token` | Secret partagé **ou** token one-shot (**l'un des deux requis**) |
| `--certificate` | Certificat relais (`efrcert_…`) si `CERT_REQUIRED=true` |
| `--tls-cert` / `--tls-key` | Certificat/clé serveur du proxy CONNECT (prod) |
| `--client-ca` | CA autorisant le cert client du bastion (prod) |
| `--allow-target` | Cible interne autorisée `IP:port` (**répétable**) |
| `--allow-http-connect-for` | Exception CONNECT en clair, durée ≤ 24 h (lab) |
| `--allow-http-client` | IP cliente autorisée pour l'exception HTTP (**répétable**, lab) |
| `--heartbeat-interval` | Intervalle de heartbeat (défaut 20 s) |
| `--dial-timeout` | Timeout de connexion vers la cible (défaut 10 s) |
| `--insecure` / `--allow-http` | **Lab uniquement** : ignore la validation TLS / autorise un bastion en HTTP |

### Variables d'environnement du bastion
| Variable | Rôle | Défaut |
|---|---|---|
| `ENDORIUMFORT_RELAY_ENROLL_SECRET` | Active l'enrôlement + secret partagé | *(vide = désactivé)* |
| `ENDORIUMFORT_RELAY_CERT_REQUIRED` | Exige un certificat relais | `true` |
| `ENDORIUMFORT_RELAY_CERT_TTL_SECONDS` | Durée de vie du certificat relais | `2592000` (30 j) |
| `ENDORIUMFORT_RELAY_ENROLL_TOKEN_TTL_SECONDS` | Durée de vie du token d'enrôlement | `600` (10 min) |
| `ENDORIUMFORT_RELAY_TOKEN_TTL_SECONDS` | Durée de vie du token de session relais | `86400` (24 h) |
| `ENDORIUMFORT_RELAY_HEARTBEAT_STALE_SECONDS` | Seuil « offline » si pas de heartbeat | `90` |

### Endpoints bastion (admin, `resources.manage`)
`POST /api/relays/certificate` · `POST /api/relays/enrollment-token` · `POST /api/relays/assign` · `GET /api/relays` · `GET /api/relays/config` · `GET /api/relays/resolve/<id>`
Côté relais : `POST /api/relays/enroll`, `POST /api/relays/heartbeat` (automatiques).

---

*Sécurité : privilégie le mTLS (§4.2) hors lab, restreins `--allow-target` au strict nécessaire, limite la source du port-forward à l'IP du bastion, et préfère un token d'enrôlement one-shot au secret partagé.*
