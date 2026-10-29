# EndoriumFort — Ressources « partage de fichiers »

**Écrit pour** : l'administrateur qui déploie et exploite le bastion, et qui veut offrir à ses utilisateurs un drive web sécurisé.
**Édition** : Community (CE) et Enterprise (EE) — aucune licence requise.

---

## 1. Principe

Une ressource de type **`fileshare`** ouvre, dans un onglet dédié, un **drive web** (dossiers, téléversement, téléchargement, partage). Chaque utilisateur y dispose de son espace personnel ; il peut partager un dossier ou un fichier avec d'autres comptes du bastion, en lecture seule ou en lecture/écriture, avec une expiration optionnelle.

Les fichiers ne sont **jamais** stockés ni servis par le bastion : ils vivent dans un **service séparé** (`fileshare/`, image `endoriumfort-files`), dans son propre conteneur et son propre volume.

```
Navigateur ──/api/──►  bastion (C++)        décide QUI peut ouvrir le drive
    │                    │  ticket signé (HMAC, 60 s, usage unique)
    │                    ▼
    └──/files/──► endoriumfort-files (Go) stocke et sert les fichiers
                  volume ef-files, réseau interne, non-root, FS en lecture seule
```

## 2. Segmentation

| Mesure | Effet |
|---|---|
| Conteneur et image distincts | Un bug ou une compromission du service de fichiers n'expose ni la base du bastion, ni le coffre, ni les sessions SSH. |
| Aucun accès à la base du bastion | Le seul lien entre les deux est la clé `ENDORIUMFORT_FILESHARE_SECRET`, qui sert uniquement à signer les tickets. |
| Réseau `files` en `internal: true` | Le service n'a aucun accès sortant ; seul le nginx du bastion le joint. |
| `read_only`, `cap_drop: ALL`, `no-new-privileges`, uid 65532 | Le service ne peut écrire que dans `/data`. |
| Accès disque via `os.Root` | Toute tentative de sortie (`..`, chemin absolu, lien symbolique) est refusée par le noyau du runtime Go, pas seulement par une vérification de chaîne. |
| Téléchargements en `attachment` + CSP `sandbox` | Un fichier HTML ou SVG déposé ne peut jamais s'exécuter dans l'origine du bastion. |
| Les octets ne traversent pas le backend C++ | nginx route `/files/` directement vers le service. |

## 3. Contrôle d'accès

1. **Ouvrir le drive** passe par le chemin habituel `POST /api/sessions` : affectation de la ressource, politiques d'accès, justification, double validation, exigence MFA, plage horaire, durée maximale. Une session apparaît dans la liste des sessions et peut être terminée par un administrateur.
2. Le propriétaire de la session (lui seul, administrateurs compris) obtient un **ticket** via `POST /api/sessions/<id>/fileshare-ticket`. Valide 60 s, utilisable une seule fois, lié à la ressource.
3. Le service de fichiers échange ce ticket contre un cookie `HttpOnly`, `SameSite=Strict`, limité au chemin `/files/api/r/<id>/`, valable **15 min** (`EF_FS_SESSION_TTL_SECONDS`). L'interface le renouvelle en redemandant un ticket au bastion.
4. **Terminer la session** sur le bastion bloque le renouvellement : le drive se ferme au plus tard à l'expiration du cookie. Retirer l'affectation de la ressource a le même effet.
5. Toute requête qui modifie quelque chose exige l'en-tête `X-EF-Files: 1` (protection CSRF).

**Partage** : la liste des personnes proposées vient de `GET /api/resources/<id>/fileshare/directory` — uniquement les comptes autorisés sur la même ressource. Un destinataire doit pouvoir ouvrir la ressource pour voir le partage. On ne peut partager que ses propres éléments (pas de re-partage). Un fichier seul est toujours partagé en lecture seule. Renommer un dossier partagé conserve le partage ; le supprimer supprime le partage.

## 4. Journalisation

- **Bastion** : `fileshare.open` (premier ticket d'une session), plus les événements habituels d'ouverture et de fin de session et les décisions de politique.
- **Service de fichiers** : chaque action (`session.open`, `list`, `download`, `upload`, `mkdir`, `rename`, `delete`, `share.create`, `share.revoke`), réussie ou refusée, est écrite dans `/data/audit.jsonl` et sur la sortie standard (logs du conteneur, collecte SIEM). Chaque ligne contient le SHA-256 de la précédente (`prev`) : supprimer ou modifier une ligne casse la chaîne.

## 5. Déploiement

### Docker Compose

Les deux fichiers compose déclarent déjà le service `endoriumfort-files`, le volume `ef-files` et le réseau `files`. Il suffit de définir la clé partagée :

```bash
# .env / .env.prod
ENDORIUMFORT_FILESHARE_SECRET=$(openssl rand -hex 32)
```

Sans clé, le service démarre mais répond `503` ; le reste du bastion n'est pas affecté.

### Variables

| Variable | Côté | Défaut | Rôle |
|---|---|---|---|
| `ENDORIUMFORT_FILESHARE_SECRET` (ou `_FILE`) | les deux | — | Clé de signature des tickets, ≥ 32 caractères. |
| `ENDORIUMFORT_FILESHARE_UPSTREAM` | bastion (nginx) | — | URL du service, ex. `http://endoriumfort-files:8090`. Vide → `/files/` répond 503. |
| `ENDORIUMFORT_FILESHARE_MAX_BODY` | bastion (nginx) | `2g` | Taille maximale d'une requête vers `/files/`. |
| `EF_FS_QUOTA_MB` | service | `10240` | Quota par drive utilisateur (0 = illimité). Les écritures d'un invité en lecture/écriture comptent sur le quota du propriétaire. |
| `EF_FS_MAX_UPLOAD_MB` | service | `2048` | Taille maximale d'un fichier. |
| `EF_FS_SESSION_TTL_SECONDS` | service | `900` | Durée du cookie entre deux renouvellements. |
| `EF_FS_MAX_ZIP_ENTRIES` | service | `20000` | Nombre maximal d'entrées d'un dossier téléchargé en `.zip`. |
| `EF_FS_LISTEN` / `EF_FS_DATA_DIR` | service | `:8090` / `/data` | Écoute et stockage. |
| `EF_FS_COOKIE_SECURE` | service | `auto` | `auto` suit `X-Forwarded-Proto`. |

### Kubernetes (Helm)

Le chart déploie le service dans un **Deployment séparé** (`<release>-endoriumfort-files`), activé par défaut (`fileshare.enabled`) : pod et PVC propres, non-root, système de fichiers en lecture seule, aucune capacité, pas de jeton de compte de service, et une **NetworkPolicy** qui n'admet que le pod du bastion et n'autorise **aucune sortie**. La clé est générée à la première installation et conservée (`<release>-endoriumfort-files-key`), ou fournie par `fileshare.secret` / `fileshare.existingSecret`. nginx joint le service par son nom complet (`clusterDomain`).

### Paquet Debian

`endoriumfort-server` installe `/opt/endoriumfort/bin/endoriumfort-files` et l'unité `endoriumfort-files.service` :

- utilisateur système dédié `endoriumfort-files`, distinct de celui du backend : les drives (`/var/lib/endoriumfort-files`, 0700) sont illisibles par le bastion ;
- clé `/etc/endoriumfort/fileshare.key` générée à l'installation, `0640 root:endoriumfort-fskey` (groupe ne contenant que les deux services) ;
- écoute sur `127.0.0.1:8090` uniquement, `IPAddressDeny=any` (aucune sortie réseau), aucune capacité, filtre seccomp `@system-service`, `ProtectSystem=strict` (score `systemd-analyze security` : 1.2) ;
- réglages dans `/etc/endoriumfort/fileshare.env` (`EF_FS_QUOTA_MB`, `EF_FS_MAX_UPLOAD_MB`…).

### Développement

`./run-dev.sh` compile et lance le service si Go est installé (données et clé dans `.fileshare-dev/`). Le serveur Vite relaie `/files` vers `EF_FILES_TARGET` (`http://localhost:8090` par défaut).

## 6. Créer une ressource

Administration → Ressources → nouvelle ressource → protocole **Partage de fichiers**. L'adresse est remplacée par un simple libellé et il n'y a pas de port. Affectez ensuite la ressource aux utilisateurs ou groupes concernés, comme pour toute autre ressource ; les règles d'accès (justification, approbation, niveau de risque) s'appliquent normalement.

## 7. Suppression d'une ressource

Supprimer une ressource `fileshare` supprime aussi son espace : le bastion envoie au service un **ordre de purge** signé avec la même clé (type `purge`, valable 60 s, usage unique) sur `POST /internal/spaces/<id>/purge`. Cette route n'est pas sous `/files/` : le reverse proxy ne l'expose jamais aux navigateurs. Les sessions de drive ouvertes sur l'espace sont coupées, les fichiers et partages supprimés. Le résultat est journalisé des deux côtés (`fileshare.purge` sur le bastion, `space.purge` dans le service), avec trois tentatives en arrière-plan.

Si le service était injoignable, l'événement `fileshare.purge` porte `outcome: failed` et la commande à lancer. Les espaces restants se gèrent en ligne de commande :

```bash
docker exec endoriumfort-files /endoriumfort-files spaces      # id, utilisateurs, octets
docker exec endoriumfort-files /endoriumfort-files purge 12    # supprime l'espace 12
# paquet Debian :
sudo -u endoriumfort-files EF_FS_DATA_DIR=/var/lib/endoriumfort-files /opt/endoriumfort/bin/endoriumfort-files spaces
```

## 8. Limites actuelles

- Le stockage est local au volume du service : sauvegardez-le comme les données du bastion. Pas de chiffrement applicatif au repos (utilisez un volume chiffré).
- Une seule instance du service : les sessions de drive sont en mémoire (un redémarrage oblige seulement l'interface à redemander un ticket, ce qu'elle fait seule).
