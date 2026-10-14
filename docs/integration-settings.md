# EndoriumFort — Configuration des intégrations depuis l'interface

**Écrit pour** : l'administrateur du bastion qui configure LDAP, le SSO, l'ITSM, le SIEM ou la politique de transfert RBI sans redéployer.
**Édition** : le magasin de configuration et son API sont dans le cœur (CE + EE) ; l'écran d'administration qui les expose fait partie de l'édition Enterprise, et la plupart des intégrations concernées sont elles-mêmes sous licence EE.

---

## 1. Principe

Chaque intégration lit sa configuration par un seul chemin : `env_flag_enabled`, `env_string_value`, `env_int_value` (et, pour les clés OIDC construites par fournisseur, `dynamic_env_*`). Ces fonctions consultent d'abord un **magasin en base**, puis l'environnement, puis la valeur par défaut compilée :

```
magasin (UI)  →  variable d'environnement (Helm, compose)  →  défaut
```

Conséquences pratiques :

- **Ce que montre l'UI est ce qui tourne.** Une valeur enregistrée dans l'interface a la priorité ; le champ affiche alors « remplace l'environnement » si une variable existe aussi, au lieu de laisser croire qu'une valeur Helm s'applique encore.
- **Revenir en arrière** se fait par **Revenir à l'environnement**, qui supprime la ligne stockée. La variable d'environnement reprend effet, sans redémarrage.
- **Les changements sont immédiats.** La lecture suivante voit la nouvelle valeur : pour le SIEM, c'est le lot suivant ; pour LDAP, la connexion suivante.
- **Aucun appel supplémentaire en base sur le chemin chaud.** Le magasin est un cache mémoire ; la base n'est lue qu'au démarrage et par un fil de rafraîchissement.

## 2. Ce qui est réglable, et ce qui ne l'est pas

Seules les clés du **catalogue** (`backend/src/settings.cc`) peuvent être écrites : 121 clés réparties en `siem`, `ldap`, `sso`, `itsm`, `rbi`, `general`. Le catalogue porte aussi le type, les bornes, les valeurs d'énumération et l'aide affichée — une clé ajoutée là apparaît dans l'UI sans toucher au frontend.

Le catalogue est une **frontière de sécurité**, pas une liste de confort. En sont absentes, et le resteront :

| Catégorie | Exemples | Pourquoi |
|---|---|---|
| Exécutables et arguments de processus | `ENDORIUMFORT_RBI_CHROMIUM`, `_HELPER`, `_FLAGS`, `_ENGINE` | configurer le bastion ne doit pas permettre d'exécuter du code dedans |
| Base de confiance | `ENDORIUMFORT_LICENSE`, `ENDORIUMFORT_VAULT_KEY`, `ENDORIUMFORT_CLUSTER_SHARED_SECRET`, `ENDORIUMFORT_RELAY_ENROLL_SECRET` | une session web ne doit pas pouvoir redéfinir l'entitlement ni le chiffrement au repos |
| Démarrage et stockage | `ENDORIUMFORT_PORT`, `ENDORIUMFORT_DB_DSN`, TTL de jetons | ces valeurs ne sont lues qu'au démarrage ; les rendre modifiables à chaud ne voudrait rien dire |
| Le magasin lui-même | `ENDORIUMFORT_SETTINGS_REFRESH_SECONDS` | il gouverne le mécanisme |

Les clés du premier groupe sont lues avec `getenv` direct, donc elles sont hors d'atteinte même en cas d'erreur de catalogue — et un test (`backend/tests/settings_test.cc`) le vérifie.

## 3. Validation

Une valeur est validée **avant** d'être stockée, et un formulaire est refusé **en entier** : un opérateur qui se trompe sur un champ récupère son formulaire, pas la moitié appliquée.

| Type | Contrôle |
|---|---|
| `bool` | `1/0`, `true/false`, `yes/no`, `on/off` ; normalisé en `1`/`0` |
| `int` | entier strict, **refusé hors bornes** plutôt que silencieusement ramené dedans |
| `enum` | doit figurer dans la liste ; insensible à la casse |
| `url` | URL `http://` ou `https://` absolue — un `file://` est refusé, parce que la valeur part dans le client HTTP brut |
| tous | pas de caractère de contrôle (ces valeurs finissent dans des lignes syslog, des requêtes HTTP et des DN LDAP, où un retour à la ligne est une injection), 4096 octets maximum |

Une valeur **vide** signifie « pas de valeur » : elle efface la ligne stockée. C'est la même chose que **Revenir à l'environnement**.

## 4. Secrets

Les champs secrets (`ENDORIUMFORT_SIEM_WEBHOOK_TOKEN`, `ENDORIUMFORT_SIEM_SPLUNK_TOKEN`, `ENDORIUMFORT_ITSM_SERVICENOW_PASSWORD`, `ENDORIUMFORT_ITSM_JIRA_TOKEN`, les `*_CLIENT_SECRET` OIDC) :

- sont chiffrés en **AES-256-GCM** avec `ENDORIUMFORT_VAULT_KEY` avant d'aller en base (`aes256:v1:iv:tag:ciphertext`) ;
- ne sont **jamais renvoyés** par l'API : le champ indique seulement `configured: true/false` ;
- sont **refusés** si aucune clé de coffre n'est configurée, au lieu d'être stockés en clair ;
- ne sont pas réécrits par un champ laissé vide — remplacer demande de saisir une nouvelle valeur, effacer demande le bouton explicite.

Si la clé de coffre change ou disparaît, les lignes secrètes deviennent illisibles et sont **ignorées** au chargement : l'intégration retombe sur l'environnement plutôt que de recevoir un identifiant vide.

## 5. API

| Méthode | Route | Permission |
|---|---|---|
| `GET` | `/api/settings/integrations` | `settings.manage` |
| `PUT` | `/api/settings/integrations` | `settings.manage` |

`settings.manage` est une nouvelle permission du catalogue ; le rôle **admin** l'obtient d'office, `operator` et `auditor` non.

Lecture :

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  https://bastion/api/settings/integrations | jq '.items[] | select(.source != "default")'
```

Chaque élément porte : `key`, `group`, `subgroup`, `kind`, `label`, `hint`, `default`, `value` (vide pour un secret), `source` (`store` | `env` | `default`), `configured`, `envShadowed`, `secret`, `updatedAt`, `updatedBy`, et `min`/`max` ou `enumValues` selon le type.

Écriture — `null` efface une clé :

```bash
curl -s -X PUT https://bastion/api/settings/integrations \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"values":{
        "ENDORIUMFORT_SIEM_SYSLOG_ENABLED": true,
        "ENDORIUMFORT_SIEM_SYSLOG_HOST": "victorialogs.monitoring.svc.cluster.local",
        "ENDORIUMFORT_SIEM_SYSLOG_PORT": 5514,
        "ENDORIUMFORT_SIEM_SYSLOG_PROTOCOL": "tcp",
        "ENDORIUMFORT_SIEM_HOSTNAME": null
      }}'
```

Réponses :

| Code | Signification |
|---|---|
| `200` | tout est appliqué (`{"status":"ok","applied":n}`) |
| `400` | au moins une valeur est invalide — **rien n'a été appliqué** ; `rejected[]` donne la clé et la raison |
| `403` | permission `settings.manage` absente |
| `500` | la validation est passée mais une écriture a échoué ; `rejected[]` dit laquelle |

## 6. Traçabilité

Chaque modification écrit un événement d'audit, donc exportable vers le SIEM comme le reste :

| Événement | Charge utile |
|---|---|
| `settings.integration.updated` | `key`, et `value` — ou `***` pour un secret, où le fait du changement est tout l'enregistrement |
| `settings.integration.cleared` | `key` |

Le `updated_by` de la ligne stockée conserve qui a posé la valeur, visible dans l'UI et dans l'API.

## 7. Haute disponibilité

Le magasin est en base, donc partagé entre les nœuds quand ils partagent un PostgreSQL. Un nœud applique sa propre écriture tout de suite ; les autres rechargent le magasin toutes les **15 s** (`ENDORIUMFORT_SETTINGS_REFRESH_SECONDS`, `0` pour ne recharger qu'au démarrage). Une erreur transitoire de base **ne vide pas** le cache en place : la valeur connue reste appliquée.

En SQLite, chaque nœud a sa propre base — la configuration n'est donc pas partagée. C'est la même limite que pour le reste des données, et la raison du passage à PostgreSQL en HA.

## 8. GitOps

Les deux approches coexistent. Si le dépôt doit rester la source de vérité, pose les valeurs dans les `values` Helm et **ne les édite pas dans l'UI** : l'écran signale toute clé stockée qui masque l'environnement, ce qui rend la dérive visible en un coup d'œil. Pour repartir de l'état déclaré, « Revenir à l'environnement » sur les clés concernées.
