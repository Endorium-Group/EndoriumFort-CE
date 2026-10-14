# EndoriumFort — Export SIEM / logging

**Écrit pour** : l'administrateur du bastion qui branche le journal d'audit sur un SIEM ou une plateforme de logs (VictoriaLogs, Splunk, syslog d'entreprise) pour en faire un SOC.
**Édition** : Enterprise (EE) — l'export SIEM nécessite une **licence EE active**.

---

## 1. Principe

Chaque événement du journal d'audit est poussé **au fil de l'eau** vers les canaux activés, par un thread dédié :

```
append_audit()  →  file en mémoire (bornée)  →  worker  →  canal(aux)  →  ton collecteur
```

Points à retenir :

- **Le bastion n'attend jamais le collecteur.** L'écriture du journal local (fichier chaîné par HMAC) reste la source de vérité ; l'export est asynchrone.
- **Un envoi en échec est réessayé** avec un back-off exponentiel avant d'être abandonné. Un collecteur qui redémarre ne crée pas de trou dans la timeline.
- **À l'arrêt, le reliquat est vidé** pendant quelques secondes au lieu d'être jeté.
- **Si le collecteur est injoignable trop longtemps**, la file sature et les événements **les plus anciens** sont abandonnés (compteur `dropped`) : on préfère perdre de l'historique que l'événement en cours.
- Le worker ne démarre que s'il existe au moins un canal activé **et** configuré : un bastion sans SIEM ne paie rien.

> L'export est une copie, pas un déport. Le journal local et sa chaîne d'intégrité restent en place : le SIEM sert à la corrélation et à l'alerte, pas de stockage de référence.

---

## 2. Ce qui est envoyé

Chaque événement devient **un objet JSON plat**. Les noms sont stables : ce sont eux que tes règles de détection utilisent.

| Champ | Exemple | Signification |
|---|---|---|
| `_time` | `2026-10-14T08:30:00Z` | horodatage de l'événement (RFC 3339, UTC) |
| `_msg` | `session.create by alice (admin) on srv-01 from 192.0.2.9` | résumé lisible, pour l'œil humain |
| `event_type` | `auth.login.failure` | type complet |
| `event_category` | `auth` | premier segment du type |
| `event_action` | `login.failure` | le reste du type |
| `outcome` | `success` \| `failure` \| `denied` | verdict |
| `severity` / `level` | `critical` \| `error` \| `warning` \| `notice` \| `info` | criticité déduite du type |
| `event_id` | `4821` | identifiant d'audit (compteur **par démarrage**, pas unique entre redémarrages) |
| `actor` | `alice` | qui a agi |
| `actor_role` | `admin` | rôle de l'acteur |
| `product` | `endoriumfort` | émetteur |
| `host` | `bastion-1` | nom d'hôte du bastion (`ENDORIUMFORT_SIEM_HOSTNAME` sinon le hostname système) |
| `node_id` | `node-a` | nœud du cluster, pour distinguer les membres en HA |
| `version` | `1.0.35` | version du bastion |

Puis les clés du payload, **promues** vers des noms stables quand elles sont connues :

| Clé du payload | Champ exporté |
|---|---|
| `sessionId` | `session_id` |
| `resourceId`, `resourceName` | `resource_id`, `resource_name` |
| `sourceIp`, `ip` | `source_ip` |
| `sourceUserAgent`, `userAgent` | `user_agent` |
| `target`, `protocol`, `port` | `target`, `protocol`, `target_port` |
| `username`, `user`, `userId`, `role` | `target_user`, `target_user_id`, `target_role` |
| `status`, `reason`, `justification`, `error` | idem (`status`, `reason`, …) |
| `riskLevel`, `policyDecision` | `risk_level`, `policy_decision` |
| `ticketId`, `leaseId`, `recordingId` | `ticket_id`, `lease_id`, `recording_id` |
| `path`, `method` | `http_path`, `http_method` |

Toute autre clé est conservée **préfixée** `ef_` (`ttlSeconds` → `ef_ttlSeconds`), y compris les sous-objets aplatis en `ef_policy_mfa_required`. Le préfixe garantit qu'un payload ne peut jamais écraser un champ réservé de la plateforme — ni usurper `actor`, `host` ou `severity`.

**Hygiène** : chaque valeur est nettoyée avant sérialisation (caractères de contrôle retirés, UTF-8 invalide remplacé, valeur tronquée à 2 Ko). Un payload mal formé ne peut donc pas faire rejeter un lot entier par le collecteur.

### Criticité attribuée

| `severity` | syslog | Déclencheurs (motifs dans le type) |
|---|---|---|
| `critical` | 2 | `incident`, `containment`, `compromise`, `breakglass`, `tamper` |
| `error` | 3 | échecs et refus : `auth.login.failure`, `command_guard.block`, `*.rejected`, `*.rate_limited` |
| `warning` | 4 | `anomaly`, `detection`, `expired`, `revoked`, `quarantine` |
| `notice` | 5 | changements d'administration : `resource.*`, `user.*`, `license.*`, `cluster.*` |
| `info` | 6 | activité ordinaire : `session.create`, `session.close`, … |

---

## 3. Canaux

| Canal | `id` | Transport | État |
|---|---|---|---|
| Syslog | `syslog` | RFC 5424 ou RFC 3164, en UDP / TCP / TLS | disponible |
| JSON Webhook | `json_webhook` | `POST` HTTP(S), objet JSON ou NDJSON | disponible |
| Splunk HEC | `splunk` | `POST` HTTP(S) vers le collecteur HEC | disponible |
| Microsoft Sentinel | `sentinel` | — | pas encore implémenté (grisé dans l'UI) |

Chaque canal est **activé** par un drapeau et **configuré** par son adresse. Les deux sont nécessaires.

### Variables communes

| Variable | Défaut | Rôle |
|---|---|---|
| `ENDORIUMFORT_SIEM_HOSTNAME` | hostname système | nom d'hôte estampillé sur les événements |
| `ENDORIUMFORT_SIEM_QUEUE_LIMIT` | `20000` | taille de la file ; au-delà, les plus anciens sont abandonnés |
| `ENDORIUMFORT_SIEM_BATCH_MAX` | `50` | événements regroupés par envoi |
| `ENDORIUMFORT_SIEM_RETRY_ATTEMPTS` | `4` | tentatives par lot |
| `ENDORIUMFORT_SIEM_RETRY_BASE_MS` | `1000` | premier délai de back-off (doublé ensuite) |
| `ENDORIUMFORT_SIEM_RETRY_MAX_MS` | `30000` | plafond du back-off |
| `ENDORIUMFORT_SIEM_HEARTBEAT_SECONDS` | `300` | battement `integration.siem.heartbeat` ; `0` pour désactiver |
| `ENDORIUMFORT_SIEM_DRAIN_SECONDS` | `5` | budget de vidage de la file à l'arrêt |

### Syslog

| Variable | Défaut | Rôle |
|---|---|---|
| `ENDORIUMFORT_SIEM_SYSLOG_ENABLED` | `0` | active le canal |
| `ENDORIUMFORT_SIEM_SYSLOG_HOST` | — | hôte du collecteur (**requis**) |
| `ENDORIUMFORT_SIEM_SYSLOG_PORT` | `514` | port |
| `ENDORIUMFORT_SIEM_SYSLOG_PROTOCOL` | `udp` | `udp` \| `tcp` \| `tls` |
| `ENDORIUMFORT_SIEM_SYSLOG_FORMAT` | `rfc5424` | `rfc5424` \| `rfc3164` |
| `ENDORIUMFORT_SIEM_SYSLOG_MESSAGE` | `cee` | `cee` (JSON préfixé `@cee:`) \| `json` \| `text` |
| `ENDORIUMFORT_SIEM_SYSLOG_FACILITY` | `13` | facility RFC 5424 (`13` = *log audit*) |
| `ENDORIUMFORT_SIEM_SYSLOG_APP_NAME` | `endoriumfort` | APP-NAME |
| `ENDORIUMFORT_SIEM_SYSLOG_FRAMING` | `octet` | TCP/TLS : `octet` (RFC 6587) \| `lf` |
| `ENDORIUMFORT_SIEM_SYSLOG_TLS_VERIFY` | `1` | vérifie la chaîne **et** le nom du certificat |
| `ENDORIUMFORT_SIEM_SYSLOG_CA_FILE` | — | bundle CA (sinon les CA système) |
| `ENDORIUMFORT_SIEM_SYSLOG_SERVER_NAME` | — | nom attendu / SNI, si différent de l'hôte |
| `ENDORIUMFORT_SIEM_SYSLOG_MAX_BYTES` | `8192` (UDP) / `65000` | troncature de la ligne |
| `ENDORIUMFORT_SIEM_SYSLOG_CONNECT_TIMEOUT_MS` | `5000` | un collecteur injoignable ne doit pas figer le worker |
| `ENDORIUMFORT_SIEM_SYSLOG_WRITE_TIMEOUT_MS` | `10000` | délai d'écriture |

Le mode `cee` produit une ligne de la forme :

```
<107>1 2026-10-14T08:30:00Z bastion-1 endoriumfort 1842 auth.login.failure [endoriumfort@0 severity="error" event="auth.login.failure" actor="alice" outcome="failure" node="node-a"] @cee: {"_time":"…","event_type":"auth.login.failure",…}
```

- le bloc `[endoriumfort@0 …]` (*structured data*) répète les champs de routage, pour un collecteur qui ne lit pas le message ;
- le cookie **`@cee:`** indique à VictoriaLogs (et à `mmjsonparse` de rsyslog) que le message est un objet JSON **à réintégrer comme champs de log**. C'est ce qui rend les requêtes par champ possibles au-dessus de syslog.

> En TCP/TLS, garde le cadrage `octet` (RFC 6587) : le récepteur lit exactement N octets, donc aucun message ne peut être coupé en deux. Le mode `lf` n'existe que pour les collecteurs qui ne savent pas faire autrement.

### JSON Webhook

| Variable | Défaut | Rôle |
|---|---|---|
| `ENDORIUMFORT_SIEM_WEBHOOK_ENABLED` | `0` | active le canal |
| `ENDORIUMFORT_SIEM_WEBHOOK_URL` | — | URL complète, query string comprise (**requis**) |
| `ENDORIUMFORT_SIEM_WEBHOOK_TOKEN` | — | envoyé en `Authorization: Bearer …` |
| `ENDORIUMFORT_SIEM_WEBHOOK_NDJSON` | `0` | `1` = un lot par requête, un objet JSON par ligne |

### Splunk HEC

| Variable | Défaut | Rôle |
|---|---|---|
| `ENDORIUMFORT_SIEM_SPLUNK_ENABLED` | `0` | active le canal |
| `ENDORIUMFORT_SIEM_SPLUNK_URL` | — | ex. `https://splunk:8088/services/collector` |
| `ENDORIUMFORT_SIEM_SPLUNK_TOKEN` | — | jeton HEC |
| `ENDORIUMFORT_SIEM_SPLUNK_INDEX` | — | index cible, facultatif |

Le `sourcetype` est `endoriumfort:audit`.

---

## 4. Recette VictoriaLogs

Deux chemins possibles. **Le webhook NDJSON est le plus fidèle** (champs typés, confirmation de livraison HTTP, lots) ; **syslog** convient si tu as déjà un listener en place.

### 4.1 Via le listener syslog

Côté VictoriaLogs, ouvre un listener et laisse-le déballer le JSON `@cee` :

```yaml
# déploiement VictoriaLogs (extrait) — k3s
args:
  - -storageDataPath=/vlogs
  - -retentionPeriod=90d
  - -syslog.listenAddr.tcp=:5514
  # champs de flux : un flux par bastion et par famille d'événements
  - -syslog.streamFields.tcp='["host","event_category"]'
  - -syslog.useLocalTimestamp.tcp=false
```

Puis côté bastion :

```bash
ENDORIUMFORT_SIEM_SYSLOG_ENABLED=1
ENDORIUMFORT_SIEM_SYSLOG_HOST=victorialogs.monitoring.svc.cluster.local
ENDORIUMFORT_SIEM_SYSLOG_PORT=5514
ENDORIUMFORT_SIEM_SYSLOG_PROTOCOL=tcp
ENDORIUMFORT_SIEM_SYSLOG_FRAMING=octet
ENDORIUMFORT_SIEM_HOSTNAME=bastion-prod-1
```

> `-syslog.listenAddr.*` est à ouvrir explicitement : par défaut VictoriaLogs n'écoute aucun port syslog. Un port < 1024 demande `CAP_NET_BIND_SERVICE`.

### 4.2 Via `/insert/jsonline` (recommandé)

Aucun listener à ouvrir : on parle à l'API d'ingestion HTTP, déjà exposée sur `9428`.

```bash
ENDORIUMFORT_SIEM_WEBHOOK_ENABLED=1
ENDORIUMFORT_SIEM_WEBHOOK_NDJSON=1
ENDORIUMFORT_SIEM_WEBHOOK_URL='http://victorialogs.monitoring.svc.cluster.local:9428/insert/jsonline?_time_field=_time&_msg_field=_msg&_stream_fields=host,event_category'
```

Les noms `_time` et `_msg` du modèle de champs sont **exactement** ceux que VictoriaLogs attend : rien à remapper.

### 4.3 Configurer depuis l'interface

Les variables du tableau ci-dessus sont aussi réglables dans **Administration → Intégrations**, sans redéployer. Deux règles à connaître :

- **Une valeur posée dans l'UI a la priorité** sur la variable d'environnement correspondante. Le champ l'indique (« remplace l'environnement ») plutôt que de laisser croire qu'une valeur Helm s'applique encore. Le bouton **Revenir à l'environnement** efface la ligne stockée.
- **Les secrets** (token de webhook, token HEC, mot de passe ServiceNow, client secret OIDC, …) sont chiffrés en AES-256-GCM avec `ENDORIUMFORT_VAULT_KEY` et ne sont **jamais relus** par l'API : le champ dit seulement s'il est renseigné. Sans clé de coffre, l'écriture d'un secret est refusée au lieu d'être stockée en clair.

Les changements s'appliquent **immédiatement** : le worker les prend au lot suivant, sans redémarrage. En HA, les autres nœuds rechargent le magasin toutes les 15 s (`ENDORIUMFORT_SETTINGS_REFRESH_SECONDS`).

Ce que l'UI ne permet **pas** de régler, volontairement : rien qui désigne un exécutable ou passe des arguments de processus (`ENDORIUMFORT_RBI_CHROMIUM`, `_HELPER`, `_FLAGS`), ni la licence, la clé de coffre, le DSN de base ou les secrets de cluster. Configurer le bastion ne doit pas être un chemin pour exécuter du code dedans.

Détails complets, API et permissions : [Configuration des intégrations](./integration-settings.md).

### 4.4 Vérifier

Dans l'UI (**Administration → Intégrations → SIEM**), le canal doit afficher sa destination, le nombre d'envois et la date du dernier battement. Le bouton **Envoyer un test** pousse un événement **de façon synchrone** et te rend l'erreur de transport telle quelle.

En ligne de commande :

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://bastion:8080/api/integrations/siem/channels | jq '.items[], .queued, .dropped'
```

Côté VictoriaLogs :

```logsql
_time:15m product:=endoriumfort | sort by (_time) desc | limit 20
```

---

## 5. Requêtes LogsQL pour le SOC

```logsql
# Tout ce qui est grave, toutes catégories
_time:24h severity:=critical or severity:=error | sort by (_time) desc

# Rafales d'échecs d'authentification par IP source
_time:1h event_type:="auth.login.failure"
  | stats by (source_ip) count() tries
  | filter tries:>5 | sort by (tries) desc

# Commandes bloquées par le garde-fou (tentative de contournement)
_time:24h event_type:="command_guard.block"
  | stats by (actor, target) count() blocked
  | sort by (blocked) desc

# Accès hors des heures ouvrées
_time:7d event_type:="session.create" _time:day_range[20:00, 06:00)
  | sort by (_time) desc

# Un acteur qui touche un nombre inhabituel de cibles
_time:24h event_category:=session
  | stats by (actor) count_uniq(target) targets
  | filter targets:>10

# Changements d'administration (piste d'audit de conformité)
_time:7d severity:=notice | sort by (_time) desc

# Refus de politique : qui se heurte à quoi
_time:24h outcome:=denied
  | stats by (actor, event_type) count() hits
  | sort by (hits) desc

# Silence du bastion : le battement a-t-il cessé ?
_time:30m event_type:="integration.siem.heartbeat" | stats count() beats
```

### Alerte sur le silence (vmalert)

Le battement sert exactement à ça : un bastion compromis ou une chaîne d'export cassée **cesse d'émettre**, et l'absence de logs ne déclenche aucune règle classique.

```yaml
groups:
  - name: endoriumfort
    interval: 1m
    rules:
      - alert: EndoriumFortExportSilent
        expr: |
          sum(count_over_time({product="endoriumfort"} | json | event_type="integration.siem.heartbeat" [15m])) == 0
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "Plus aucun battement du bastion depuis 15 min"
```

> Adapte l'expression à ta source de métriques (vmalert sur VictoriaLogs utilise `-datasource.url` vers VictoriaLogs et la syntaxe LogsQL dans `expr`). Le principe compte plus que la ligne exacte : **alerter sur l'absence**, pas seulement sur la présence.

---

## 6. Exploitation

### Ce que l'UI et l'API exposent

`GET /api/integrations/siem/channels` (permission `resources.manage`) :

| Champ | Lecture |
|---|---|
| `items[].configured` / `enabled` / `implemented` | pourquoi un canal n'envoie rien |
| `items[].target` | destination effective, identifiants retirés |
| `items[].delivered` / `failed` / `retried` | volumétrie et santé |
| `items[].lastError`, `lastFailedAt`, `lastDeliveredAt` | diagnostic ; comparer les deux dates dit si c'est réglé |
| `queued`, `dropped`, `lastDropAt` | saturation : `dropped > 0` = perte d'historique |
| `heartbeatSeconds`, `lastHeartbeatAt` | la chaîne est-elle vivante |
| `running` | le worker tourne |

### Symptômes courants

| Symptôme | Cause probable |
|---|---|
| `configured: false` | adresse absente (`…_HOST` / `…_URL` vide) |
| `enabled: false` | drapeau `…_ENABLED` non positionné |
| `implemented: false` | canal pas encore disponible (Sentinel) |
| `lastError: connection timed out after 5000 ms` | pare-feu qui **DROP**, mauvais port, ou service k8s inexistant |
| `lastError: TLS certificate rejected: …` | CA absente du bundle, ou nom du certificat ≠ hôte configuré |
| `dropped` qui grimpe | collecteur indisponible trop longtemps ; augmenter `QUEUE_LIMIT` ou réparer le collecteur |
| rien n'arrive, aucune erreur | licence EE absente ou expirée : l'export est une fonction Enterprise |

### Volumétrie

Un événement coûte environ 600 à 900 octets en `cee`/JSON. Le battement par défaut (300 s) ajoute ~12 événements par heure. Les événements `web.proxy_access` dominent le volume sur un bastion qui proxifie beaucoup de HTTP : c'est le premier levier si ta rétention est contrainte.

### Limites connues

- **Pas de spool sur disque.** La file est en mémoire : un `kill -9` perd ce qui n'est pas encore parti (un arrêt propre vide la file pendant `DRAIN_SECONDS`). Le journal local reste complet — le rattrapage se fait en relisant `audit-log.jsonl`.
- **`event_id` n'est pas unique entre redémarrages** (compteur par démarrage). Pour dédupliquer, utiliser `_time` + `event_type` + `actor`, ou le couple `host` + `event_id` sur une même période de fonctionnement.
- **UDP ne confirme rien.** Un envoi UDP est compté comme livré dès qu'il part. Pour un SOC, préférer `tcp` ou `tls`.
- **Microsoft Sentinel** n'a pas de transport : passer par le webhook JSON vers une Logic App / un Data Collector endpoint.

---

## 7. Déploiement k3s (Helm)

Le chart expose un bloc dédié :

```yaml
config:
  siem:
    hostname: bastion-prod-1
    heartbeatSeconds: 300
    syslog:
      enabled: true
      host: victorialogs.monitoring.svc.cluster.local
      port: 5514
      protocol: tcp
    webhook:
      enabled: false
```

Le jeton d'un webhook ou de Splunk se passe par le `Secret` existant (clés `ENDORIUMFORT_SIEM_WEBHOOK_TOKEN`, `ENDORIUMFORT_SIEM_SPLUNK_TOKEN`) plutôt qu'en clair dans les `values`. Toute variable non couverte par le bloc reste positionnable via `extraEnv`.
