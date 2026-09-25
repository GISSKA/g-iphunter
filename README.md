# G-IPHunter

> **Orchestrateur OSINT / Threat Intelligence pour analystes cybersécurité.**
> Interroge plusieurs sources publiques, corrèle les résultats et produit un
> rapport professionnel exploitable (console, JSON, HTML, PDF).

G-IPHunter n'est **pas** un simple wrapper d'API : c'est un pipeline complet
d'enrichissement, de normalisation et de scoring qui fournit une vue unique
et hiérarchisée de la posture d'une adresse IP.

---

## ✨ Fonctionnalités

- 🔎 **5 sources publiques interrogées en parallèle** (aucune clé API requise) :
  - **IPinfo Legacy** (`ipinfo.io/<IP>/json`) — géolocalisation, ASN, org, hostname.
  - **Shodan InternetDB** (`internetdb.shodan.io/<IP>`) — ports, CPE, tags, CVE.
  - **FFraud Public IP API** (`api.ffraud.com/public/ip/<IP>`) — score de fraude, VPN/Proxy/Tor, abus.
  - **ipaddress.you** (`ipaddress.you/api/ip/<IP>`) — géolocalisation, ISP, reverse DNS.
  - **ipaddress.you Blacklist** (`ipaddress.you/api/blacklist/<IP>`) — DNSBL / blacklists.
- 🧠 **Normalisation & corrélation** : identité réseau, localisation, exposition, réputation, menaces.
- 📊 **Score de risque 0–100** avec niveau (`faible`, `moyen`, `élevé`, `critique`) et facteurs contributifs détaillés.
- 🛡️ **Résilience** : un timeout ou une API indisponible n'interrompt jamais l'analyse.
- 📁 **Exports** : `JSON`, `HTML` (dark theme autonome), `PDF` (rapport professionnel via ReportLab).
- 🌐 **Analyse en lot** avec résumé final hiérarchisé mettant en évidence les IP à investiguer.
- 🚦 **Code de sortie 3** si au moins une IP dépasse le seuil de risque `50/100` — utilisable en CI.

> ⚠️ **Avertissement** — Le score de risque est un **indicateur d'aide à la décision**.
> Il ne constitue en aucun cas une preuve de malveillance et doit toujours être
> corroboré par une analyse contextuelle humaine.

---

## 📦 Installation

### Prérequis

- **Python 3.9 ou supérieur** — [python.org/downloads](https://www.python.org/downloads/)
- **Git** — [git-scm.com](https://git-scm.com/)
- **pipx** — [pipx.pypa.io](https://pipx.pypa.io)

> 💡 Si vous n'avez pas encore pipx :
> ```bash
> python -m pip install --user pipx
> python -m pipx ensurepath
> ```
> Puis rouvrez votre terminal.

### Installer G-IPHunter

```bash
git clone https://github.com/GISSKA/g-iphunter.git
cd g-iphunter
pipx install .

C'est tout. La commande `g-iphunter` est désormais disponible partout dans votre terminal — dans n'importe quel dossier, sans activation préalable.

### Vérifier

```bash
g-iphunter --version
# G-IPHunter 1.0.0
```

### Mettre à jour

```bash
cd g-iphunter
git pull
pipx install . --force
```

### Désinstaller

```bash
pipx uninstall g-iphunter
```

Puis, si vous ne voulez plus du code source :

```bash
cd ..
rm -rf g-iphunter       # Linux / macOS
rmdir /s g-iphunter     # Windows (CMD)
```

### Pour contribuer ou modifier le code

Installez en mode **éditable** — la commande `g-iphunter` pointera directement vers votre dossier source :

```bash
cd g-iphunter
pipx install -e .
```

Vous modifiez un fichier, vous relancez `g-iphunter` — la modification est prise en compte immédiatement, sans réinstallation.

> 💡 **Pourquoi pipx ?** Il installe G-IPHunter dans un environnement isolé. Rien n'est ajouté à votre Python système, rien n'entre en conflit avec vos autres projets. C'est la méthode recommandée pour tout outil en ligne de commande.

---

## 🚀 Utilisation

### Analyser une seule IP

```bash
g-iphunter 8.8.8.8
```

Affiche un rapport console complet : identité réseau, localisation, exposition, réputation, statut des sources et points clés à retenir.

### Analyser plusieurs IP

```bash
g-iphunter 1.1.1.1 8.8.8.8 9.9.9.9
```

Chaque IP est analysée en parallèle, puis un **résumé final hiérarchisé** classe les IP par score de risque et met en évidence celles nécessitant une investigation humaine.

### Analyser un fichier de liste

**`suspects.txt`**

```text
# Une IP par ligne. '#' pour commenter.
185.220.101.5
45.155.205.233
91.240.118.172   # extrait du log firewall
103.75.190.14
```

```bash
g-iphunter --file suspects.txt
```

### Générer un rapport à livrer

```bash
g-iphunter 185.220.101.5 \
  --pdf rapport_incident.pdf \
  --html rapport_incident.html \
  --json rapport_incident.json
```

| **Fichier**             | **Usage typique**                                           |
| ----------------------- | ----------------------------------------------------------- |
| `rapport_incident.pdf`  | Pièce jointe à un mail client — rendu professionnel.        |
| `rapport_incident.html` | Version web autonome (CSS embarqué) — à héberger ou ouvrir. |
| `rapport_incident.json` | Version machine — à archiver ou à traiter dans un SIEM.     |

### Sortie discrète (script, cron, bot)

```bash
g-iphunter 8.8.8.8 --quiet --json resultat.json
```

Aucune sortie console, seul `resultat.json` est écrit. Idéal pour une intégration dans un pipeline.

### Options disponibles

| **Option**        | **Description**                                                |
| ----------------- | -------------------------------------------------------------- |
| `ips...`          | Une ou plusieurs adresses IP à analyser.                       |
| `-f, --file PATH` | Fichier texte contenant une IP par ligne (`#` pour commenter). |
| `--json PATH`     | Écrit le rapport JSON.                                         |
| `--html PATH`     | Écrit le rapport HTML.                                         |
| `--pdf PATH`      | Écrit le rapport PDF.                                          |
| `--timeout S`     | Timeout HTTP par source en secondes (défaut `10`).             |
| `--concurrency N` | Nombre d'IP analysées en parallèle (défaut `5`).               |
| `--no-color`      | Désactive la coloration ANSI.                                  |
| `-q, --quiet`     | Pas de rapport console détaillé.                               |
| `-v, --verbose`   | Affiche la progression sur `stderr`.                           |
| `--version`       | Affiche la version de l'outil.                                 |

### Exemples d'usage courant

```bash
# Timeout plus court (réseau lent ou instable)
g-iphunter 8.8.8.8 --timeout 5

# Analyser une longue liste en parallèle
g-iphunter --file big_list.txt --concurrency 20

# Rediriger vers un fichier sans codes ANSI
g-iphunter 8.8.8.8 --no-color > rapport.txt

# Suivre la progression sur une grosse liste
g-iphunter --file big_list.txt --verbose
```
