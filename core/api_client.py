import os
import time
import requests
from datetime import datetime
from typing import Dict, List, Tuple, Set, Optional

# Ces constantes pourraient aller dans config.py plus tard
API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

class NVDClient:
    """
    Gère exclusivement les communications réseau avec la NVD et le CISA.
    Aucune logique d'affichage (UI) ne doit se trouver ici.
    """
    def __init__(self):
        self.api_cache = {}
        self.last_api_call = None
        self.cisa_kev_set: Set[str] = set()
        self.cisa_loaded = False
        
        # Gestion propre de la clé API via l'environnement
        self.api_key = os.getenv("NVD_API_KEY")
        self.delay = 0.6 if self.api_key else 6.0
        
        self.headers = {"apiKey": self.api_key} if self.api_key else {}

    def load_cisa_kev(self) -> Tuple[bool, str]:
        """
        Charge la base CISA. Retourne un tuple (Succès, Message d'erreur éventuel).
        """
        try:
            response = requests.get(CISA_KEV_URL, timeout=10)
            response.raise_for_status() # Lève une exception si HTTP 4xx/5xx
            data = response.json()
            
            for vuln in data.get("vulnerabilities", []):
                self.cisa_kev_set.add(vuln.get("cveID"))
                
            self.cisa_loaded = True
            return True, ""
            
        except requests.exceptions.RequestException as e:
            self.cisa_loaded = False
            return False, f"Erreur réseau lors du contact avec CISA: {e}"
        except ValueError:
            self.cisa_loaded = False
            return False, "Le flux CISA a renvoyé des données invalides (non-JSON)."

    def is_cve_in_kev(self, cve_id: str) -> bool:
        """Vérifie si une CVE est connue comme activement exploitée."""
        return cve_id in self.cisa_kev_set

    def _apply_rate_limit(self):
        """Gère le délai d'attente imposé par l'API NVD."""
        if self.last_api_call is not None:
            elapsed = (datetime.now() - self.last_api_call).total_seconds()
            wait_time = self.delay - elapsed
            if wait_time > 0:
                time.sleep(wait_time)
        self.last_api_call = datetime.now()

    def fetch_nvd_page(self, params: Dict) -> Tuple[List, int, Optional[int]]:
        """
        Effectue un appel unique à l'API NVD (une seule page).
        Retourne : (Liste des vulnérabilités, Total des résultats, Code d'erreur HTTP ou None)
        """
        # Utilisation du cache pour éviter les appels redondants
        cache_key = str(sorted(params.items()))
        if cache_key in self.api_cache:
            return self.api_cache[cache_key]

        self._apply_rate_limit()

        try:
            response = requests.get(API_BASE_URL, params=params, headers=self.headers, timeout=30)
            if response.status_code != 200:
                return [], 0, response.status_code

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)

            # Mise en cache
            self.api_cache[cache_key] = (vulnerabilities, total_results, None)
            return vulnerabilities, total_results, None

        except requests.exceptions.RequestException:
            # Code 999 arbitraire pour désigner un timeout / erreur réseau interne
            return [], 0, 999
