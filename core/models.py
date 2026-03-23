from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class CVEDetails:
    """Modèle représentant une CVE formatée, prêt à être affiché ou exporté."""
    id: str
    published: str
    modified: str
    description: str
    score: str
    severity: str
    vector: str
    cwe: str
    poc_status: str
    exploit_refs: List[str]
    is_critical: bool
    raw_data: Dict[str, Any] = field(repr=False) # Conserve le JSON original brut

    @property
    def numeric_score(self) -> float:
        """Propriété utilitaire pour faciliter les tris par score."""
        try:
            return float(self.score)
        except (ValueError, TypeError):
            return 0.0

def parse_cve_item(cve_item: Dict, is_in_kev: bool) -> CVEDetails:
    """Extrait les champs pertinents du JSON brut de l'API NVD."""
    cve = cve_item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    published = cve.get("published", "").split("T")[0]
    last_modified = cve.get("lastModified", "").split("T")[0]
    
    descriptions = cve.get("descriptions", [])
    desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
    
    metrics = cve.get("metrics", {})
    score, severity, vector = "N/A", "N/A", "N/A"
    
    cvss_data = None
    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
    elif "cvssMetricV30" in metrics:
        cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
    
    if cvss_data:
        score = cvss_data.get("baseScore", "N/A")
        severity = cvss_data.get("baseSeverity", "N/A")
        vector = cvss_data.get("vectorString", "N/A")
    elif "cvssMetricV2" in metrics:
        v2_data = metrics["cvssMetricV2"][0]
        score = v2_data.get("cvssData", {}).get("baseScore", "N/A")
        severity = v2_data.get("baseSeverity", "N/A")

    weaknesses = cve.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang") == "en" and desc.get("value") != "NVD-CWE-noinfo":
                cwe_ids.append(desc["value"])
    cwe_str = ", ".join(cwe_ids) if cwe_ids else "N/A"

    exploit_refs = []
    has_poc_ref = False
    
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        is_exploit_link = False
        if "Exploit" in tags: is_exploit_link = True
        elif any(x in url for x in ["exploit-db", "packetstorm", "github.com/offensive-security"]): 
            is_exploit_link = True
        
        if is_exploit_link:
            has_poc_ref = True
            exploit_refs.append(url)

    poc_status = "No"
    if is_in_kev: poc_status = "ACTIVE (CISA)"
    elif has_poc_ref: poc_status = "Yes (Probable)"

    is_critical = severity in ["CRITICAL", "HIGH"] or is_in_kev

    return CVEDetails(
        id=cve_id, published=published, modified=last_modified,
        description=desc_text, score=str(score), severity=severity,
        vector=vector, cwe=cwe_str, poc_status=poc_status,
        exploit_refs=exploit_refs, is_critical=is_critical, raw_data=cve_item
    )
