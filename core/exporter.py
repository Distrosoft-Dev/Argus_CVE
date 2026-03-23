import json
from pathlib import Path
from core.models import CVEDetails

# Gestion des dossiers de sortie
SAVED_FOLDER = Path("saved_cves")
EXPORT_FOLDER = Path("exported_cves")

def init_folders():
    """Crée les dossiers d'export s'ils n'existent pas."""
    SAVED_FOLDER.mkdir(exist_ok=True)
    EXPORT_FOLDER.mkdir(exist_ok=True)

def save_cve_json(cve: CVEDetails) -> Path:
    """Sauvegarde le JSON brut de la CVE sur le disque."""
    filename = f"{cve.id.replace('-', '_')}.json"
    filepath = SAVED_FOLDER / filename
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(cve.raw_data, f, indent=2)
        
    return filepath

def export_cve_markdown(cve: CVEDetails) -> Path:
    """Exporte un rapport lisible de la CVE en Markdown."""
    filename = f"{cve.id.replace('-', '_')}.md"
    filepath = EXPORT_FOLDER / filename

    poc_section = "No public POC identified in NVD/CISA sources."
    if cve.exploit_refs or "ACTIVE" in cve.poc_status:
        links = "\n".join([f"- {url}" for url in cve.exploit_refs])
        status_alert = ""
        if "ACTIVE" in cve.poc_status:
            status_alert = "**⚠️ WARNING: This vulnerability is known to be actively exploited (Source: CISA KEV).**\n\n"
        
        poc_section = f"""### Links to Detected Exploits / POCs:
{status_alert}{links if links else "- (Referenced by CISA but no direct link)"}"""

    markdown_content = f"""# Vulnerability Analysis: {cve.id}

| Field | Detail |
|-------|--------|
| **Published Date** | {cve.published} |
| **Last Update** | {cve.modified} |
| **CVSS Score** | {cve.score} ({cve.severity}) |
| **CVSS Vector** | `{cve.vector}` |
| **Weakness (CWE)** | {cve.cwe} |

## Description
{cve.description}

## Exploit Availability (POC)
**Status : {cve.poc_status}**

{poc_section}

---
*DistroSoft - Argus CVE*
"""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(markdown_content)
        
    return filepath
