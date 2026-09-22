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