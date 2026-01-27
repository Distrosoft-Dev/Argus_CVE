import requests
import json
import os
import sys
import time
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Set

# External libraries check
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, IntPrompt
    from rich.text import Text
    from rich import box
except ImportError:
    print("Error: The 'rich' library is missing. Please install it using 'pip install rich'")
    sys.exit(1)

# Config
API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RESULTS_PER_PAGE = 20
SAVED_FOLDER = Path("saved_cves")
EXPORT_FOLDER = Path("exported_cves")
MAX_DATE_RANGE_DAYS = 110 

class CVEAnalyzer:
    def __init__(self):
        self.console = Console()
        self.api_cache = {}
        self.last_api_call = None
        
        # ==============================================================================
        # [CONFIGURATION API KEY]
        self.api_key_input = ""  
        # ==============================================================================

        # Handle API Key Logic and Delay
        self.api_key = None
        self.delay = 6.0 # Default speed

        if self.api_key_input and len(self.api_key_input) > 10:
            self.api_key = self.api_key_input.strip()
            self.delay = 0.6
        elif os.getenv("NVD_API_KEY"):
            self.api_key = os.getenv("NVD_API_KEY")
            self.delay = 0.6

        self.cisa_kev_set: Set[str] = set()
        
        # mkdir
        SAVED_FOLDER.mkdir(exist_ok=True)
        EXPORT_FOLDER.mkdir(exist_ok=True)
        
        # Load CISA
        self._load_cisa_kev()

    def _load_cisa_kev(self):
        try:
            response = requests.get(CISA_KEV_URL, timeout=5)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get("vulnerabilities", []):
                    self.cisa_kev_set.add(vuln.get("cveID"))
        except Exception:
            pass

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def _rate_limit(self):
        if self.last_api_call is not None:
            elapsed = (datetime.now() - self.last_api_call).total_seconds()
            wait_time = self.delay - elapsed
            if wait_time > 0:
                time.sleep(wait_time)
        self.last_api_call = datetime.now()

    def _fetch_single_page(self, params, headers):
        try:
            self._rate_limit()
            response = requests.get(API_BASE_URL, params=params, headers=headers, timeout=30)
            if response.status_code != 200:
                return None, response.status_code
            return response.json(), 200
        except requests.exceptions.RequestException:
            return None, 999

    def _extract_severity_score(self, cve_item: Dict) -> int:
        cve = cve_item.get("cve", {})
        metrics = cve.get("metrics", {})
        severity = "N/A"

        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV30" in metrics:
            severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV2" in metrics:
            severity = metrics["cvssMetricV2"][0]["baseSeverity"]

        weights = {
            "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "N/A": 0
        }
        return weights.get(severity, 0)

    def fetch_cves(self, start_date=None, end_date=None, keyword=None, severity_list=None, limit=None) -> Tuple[List, int]:
        base_params = {}
        if keyword: base_params["keywordSearch"] = keyword
        
        filter_severity_locally = False
        target_severities = []

        if severity_list:
            target_severities = [s.upper() for s in severity_list if s]
            if len(target_severities) == 1:
                base_params["cvssV3Severity"] = target_severities[0]
            elif len(target_severities) > 1:
                filter_severity_locally = True
        
        if limit: base_params["resultsPerPage"] = limit

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        s_clean = start_date.replace('Z', '+00:00')
        e_clean = end_date.replace('Z', '+00:00')
        s_date_obj = datetime.fromisoformat(s_clean)
        e_date_obj = datetime.fromisoformat(e_clean)
        delta = e_date_obj - s_date_obj

        all_vulnerabilities = []
        current_start = s_date_obj
        
        ranges = []
        while current_start < e_date_obj:
            current_end = current_start + timedelta(days=MAX_DATE_RANGE_DAYS)
            if current_end > e_date_obj: current_end = e_date_obj
            ranges.append((current_start, current_end))
            current_start = current_end

        if delta.days > MAX_DATE_RANGE_DAYS:
            self.console.print(f"[yellow]Date range ({delta.days} days) exceeds NVD limit. Splitting into {len(ranges)} chunks...[/yellow]")

        for r_start, r_end in ranges:
            s_str = r_start.strftime("%Y-%m-%dT%H:%M:%S.000")
            e_str = r_end.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            if delta.days > MAX_DATE_RANGE_DAYS:
                self.console.print(f"   [dim]Fetching {s_str[:10]} -> {e_str[:10]}...[/dim]")
            
            vulns, _ = self._execute_fetch(base_params, s_str, e_str, headers)
            all_vulnerabilities.extend(vulns)

        if filter_severity_locally:
            filtered_vulns = []
            for item in all_vulnerabilities:
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                sev = "N/A"
                if "cvssMetricV31" in metrics: sev = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                elif "cvssMetricV30" in metrics: sev = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
                
                if sev in target_severities:
                    filtered_vulns.append(item)
            
            all_vulnerabilities = filtered_vulns

        all_vulnerabilities.sort(
            key=lambda x: (self._extract_severity_score(x), x['cve']['published']), 
            reverse=True
        )
        
        return all_vulnerabilities, len(all_vulnerabilities)

    def _execute_fetch(self, params, start_str, end_str, headers) -> Tuple[List, int]:
        params = params.copy()
        params["pubStartDate"] = start_str
        params["pubEndDate"] = end_str
        
        cache_key = str(sorted(params.items()))
        if cache_key in self.api_cache:
            return self.api_cache[cache_key]

        data, status = self._fetch_single_page(params, headers)
        
        if status != 200:
            self.console.print(f"[bold red]API Error on chunk {start_str}: {status}[/bold red]")
            return [], 0

        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)
        
        self.api_cache[cache_key] = (vulnerabilities, total_results)
        return vulnerabilities, total_results

    def _extract_cve_details(self, cve_item: Dict) -> Dict:
        cve = cve_item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        published = cve.get("published", "").split("T")[0]
        last_modified = cve.get("lastModified", "").split("T")[0]
        descriptions = cve.get("descriptions", [])
        desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
        
        metrics = cve.get("metrics", {})
        score = "N/A"
        severity = "N/A"
        vector = "N/A"
        
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

        is_in_kev = cve_id in self.cisa_kev_set
        exploit_refs = []
        has_poc_ref = False
        
        for ref in cve.get("references", []):
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            is_exploit_link = False
            if "Exploit" in tags: is_exploit_link = True
            elif any(x in url for x in ["exploit-db", "packetstorm", "github.com/offensive-security"]): is_exploit_link = True
            
            if is_exploit_link:
                has_poc_ref = True
                exploit_refs.append(url)

        poc_status = "No"
        if is_in_kev: poc_status = "ACTIVE (CISA)"
        elif has_poc_ref: poc_status = "Yes (Probable)"

        return {
            "id": cve_id, "published": published, "modified": last_modified,
            "description": desc_text, "score": score, "severity": severity,
            "vector": vector, "cwe": cwe_str, "poc_status": poc_status,
            "exploit_refs": exploit_refs,
            "is_critical": severity in ["CRITICAL", "HIGH"] or is_in_kev,
            "raw_cve": cve
        }

    def display_cves(self, cves: List, page=1, per_page=RESULTS_PER_PAGE) -> int:
        if not cves:
            self.console.print(Panel("[italic yellow]No CVEs found.[/italic yellow]", title="Results"))
            return 0

        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, len(cves))
        page_cves = cves[start_idx:end_idx]

        table = Table(title=f"CVE Dashboard ({start_idx+1}-{end_idx} / {len(cves)}) - Sorted by Severity", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("ID & Date", style="bold cyan")
        table.add_column("Score", justify="center", width=8)
        table.add_column("Severity", width=10)
        table.add_column("POC ?", justify="center", width=12)
        table.add_column("Description", style="white")

        for i, cve_item in enumerate(page_cves, start=start_idx + 1):
            details = self._extract_cve_details(cve_item)
            score_style = "green"
            try:
                s = float(details["score"])
                if s >= 9.0: score_style = "bold red"
                elif s >= 7.0: score_style = "red"
                elif s >= 4.0: score_style = "yellow"
            except: pass
            
            poc_txt = details["poc_status"]
            poc_style = "dim"
            if "ACTIVE" in poc_txt: poc_style = "bold red blink"
            elif "Yes" in poc_txt: poc_style = "bold yellow"

            desc = details["description"]
            short_desc = (desc[:60] + "...") if len(desc) > 60 else desc

            table.add_row(
                str(i),
                f"{details['id']}\n[dim]{details['published']}[/dim]",
                f"[{score_style}]{details['score']}[/{score_style}]",
                self._get_severity_styled(details["severity"]),
                f"[{poc_style}]{poc_txt}[/{poc_style}]",
                short_desc
            )

        self.console.print(table)
        return len(page_cves)

    def _get_severity_styled(self, severity):
        colors = {
            "CRITICAL": "[bold red]CRITICAL[/bold red]",
            "HIGH": "[red]HIGH[/red]",
            "MEDIUM": "[yellow]MEDIUM[/yellow]",
            "LOW": "[green]LOW[/green]",
            "N/A": "[dim]N/A[/dim]"
        }
        return colors.get(severity, severity)

    def save_cve_info(self, cve_item):
        details = self._extract_cve_details(cve_item)
        filename = f"{details['id'].replace('-', '_')}.json"
        filepath = SAVED_FOLDER / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(cve_item, f, indent=2)
        self.console.print(f"[bold green]JSON saved: {filepath}[/bold green]")

    def export_cve_to_markdown(self, cve_item):
        data = self._extract_cve_details(cve_item)
        filename = f"{data['id'].replace('-', '_')}.md"
        filepath = EXPORT_FOLDER / filename

        poc_section = "No public POC identified in NVD/CISA sources."
        if data["exploit_refs"] or "ACTIVE" in data["poc_status"]:
            links = "\n".join([f"- {url}" for url in data["exploit_refs"]])
            status_alert = ""
            if "ACTIVE" in data["poc_status"]:
                status_alert = "**⚠️ WARNING: This vulnerability is known to be actively exploited (Source: CISA KEV).**\n\n"
            poc_section = f"""{status_alert}### Links to Detected Exploits / POCs:
{links if links else "- (Referenced by CISA but no direct link)"}
"""

        markdown_content = f"""# Vulnerability Analysis: {data['id']}

| Field | Detail |
|-------|--------|
| **Published Date** | {data['published']} |
| **Last Update** | {data['modified']} |
| **CVSS Score** | {data['score']} ({data['severity']}) |
| **CVSS Vector** | `{data['vector']}` |
| **Weakness (CWE)** | {data['cwe']} |

## Description
{data['description']}

## Exploit Availability (POC)
**Status : {data['poc_status']}**

{poc_section}

---
*DistroSoft - Argus CVE*
"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        self.console.print(f"[bold green]Markdown report exported: {filepath}[/bold green]")

    def display_detailed_cve(self, cve_item):
        self.clear_screen()
        data = self._extract_cve_details(cve_item)
        panel_text = f"""
[bold cyan]ID:[/bold cyan] {data['id']}
[bold cyan]CVSS:[/bold cyan] {data['score']} ({data['severity']})
[bold cyan]Vector:[/bold cyan] {data['vector']}
[bold cyan]CWE:[/bold cyan] {data['cwe']}
[bold cyan]POC Status:[/bold cyan] {data['poc_status']}

[bold]Description:[/bold]
{data['description']}
"""
        title_style = "bold red" if data["is_critical"] else "bold blue"
        self.console.print(Panel(panel_text, title=f"Details - {data['id']}", border_style=title_style))
        if data["exploit_refs"]:
            self.console.print("[bold yellow]Potential exploit links found! See Markdown export.[/bold yellow]")

        self.console.print("\n[bold]Options:[/bold]")
        self.console.print("[1] Save (JSON)")
        self.console.print("[2] Export Report (Markdown + POCs)")
        self.console.print("[0] Return")
        choice = IntPrompt.ask("Choice", default=0)
        if choice == 1: self.save_cve_info(cve_item)
        elif choice == 2: self.export_cve_to_markdown(cve_item)

    # -------------------------------------------------------------------------
    #  INTERACTIVE MODE
    # -------------------------------------------------------------------------
    def search_vulnerabilities(self):
        self.clear_screen()
        self.console.print(Panel("[bold]CVE Search[/bold]"))

        days = IntPrompt.ask("Search from N days", default=7)
        keyword = Prompt.ask("Keyword (optional)", default="")

        severity_options = ["Any", "Critical", "High", "Medium", "Low"]
        for i, sev in enumerate(severity_options):
            self.console.print(f"[{i}] {sev}")
        
        sev_input = Prompt.ask("Severity (0 or 1,2 etc)", default="0")
        
        selected_severities = []
        try:
            indices = [int(x.strip()) for x in sev_input.split(',') if x.strip().isdigit()]
            for idx in indices:
                if 0 < idx < len(severity_options):
                    selected_severities.append(severity_options[idx])
                elif idx == 0:
                    selected_severities = [] 
                    break
        except:
            selected_severities = []

        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        with self.console.status("[bold green]Querying NIST (this might take time if range is large)...[/bold green]"):
            cves, total = self.fetch_cves(
                start_date=start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                end_date=end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                keyword=keyword if keyword else None,
                severity_list=selected_severities
            )

        self.console.print(f"[bold green]{len(cves)} vulnerabilities found (Total in range).[/bold green]")
        
        current_page = 1
        while True:
            count = self.display_cves(cves, page=current_page)
            if count == 0 and current_page > 1:
                current_page -= 1
                continue
            elif count == 0:
                input("\nEnter to return...")
                break

            self.console.print("\n[bold]Navigation:[/bold] [1] Next [2] Previous [3] Details [0] Menu")
            choice = IntPrompt.ask("Choice", default=0)
            if choice == 0: break
            elif choice == 1:
                if (current_page * RESULTS_PER_PAGE) < len(cves): current_page += 1
                else: self.console.print("[yellow]End of results.[/yellow]")
            elif choice == 2: current_page = max(1, current_page - 1)
            elif choice == 3:
                idx = IntPrompt.ask("CVE Number (#)", default=1)
                if 1 <= idx <= len(cves):
                    self.display_detailed_cve(cves[idx-1])
                    input("\nEnter to continue...")

    def show_main_menu(self):
        ascii_art = """[bold cyan]
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗     ██████╗██╗   ██╗███████╗       
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝    ██╔════╝██║   ██║██╔════╝       
███████║██████╔╝██║  ███╗██║   ██║███████╗    ██║     ██║   ██║█████╗         
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║    ██║     ╚██╗ ██╔╝██╔══╝         
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║    ╚██████╗ ╚████╔╝ ███████╗       
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝     ╚═════╝  ╚═══╝  ╚══════╝       
[/bold cyan]"""
        while True:
            self.clear_screen()
            self.console.print(ascii_art)
            if self.cisa_kev_set:
                self.console.print(f"[bold green]✓ CISA KEV Database loaded ({len(self.cisa_kev_set)} entries)[/bold green]", justify="center")
            else:
                self.console.print("[dim]! CISA Database not loaded (offline mode or error)[/dim]", justify="center")
            
            if self.api_key:
                self.console.print("[bold green]✓ API Key Detected (Fast Mode)[/bold green]", justify="center")
            else:
                self.console.print("[dim]! No API Key (Slow Mode)[/dim]", justify="center")

            self.console.print(Panel.fit("[bold]Argus CVE[/bold]", title="Made by DistroSoft", border_style="cyan"))
            self.console.print("[1] Search Vulnerabilities\n[0] Exit")
            
            choice = IntPrompt.ask(">", default=0)
            if choice == 0: break
            elif choice == 1: self.search_vulnerabilities()

    # -------------------------------------------------------------------------
    #  CLI MODE
    # -------------------------------------------------------------------------
    def run_cli_search(self, args):
        """Executes search based on command line arguments"""
        
        # 1 Parse Severities (1,2 -> ['CRITICAL', 'HIGH'])
        severity_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
        selected_severities = []
        if args.severity:
            try:
                indices = [int(x.strip()) for x in args.severity.split(',') if x.strip().isdigit()]
                for idx in indices:
                    if idx in severity_map:
                        selected_severities.append(severity_map[idx])
            except Exception as e:
                self.console.print(f"[red]Error parsing severities: {e}[/red]")
                sys.exit(1)

        # 2 Date Calculation
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=args.days)

        self.console.print(f"[bold]Argus CVE CLI[/bold] | keyword='{args.keyword}' | days={args.days} | severity={selected_severities}")

        # 3 Fetch
        with self.console.status("[bold green]Fetching data...[/bold green]"):
            cves, total = self.fetch_cves(
                start_date=start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                end_date=end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                keyword=args.keyword,
                severity_list=selected_severities,
                limit=args.limit
            )

        # 4 Display Results
        self.console.print(f"[bold green]{len(cves)} found.[/bold green]")
        self.display_cves(cves, page=1, per_page=100) # Show up to 100 in CLI

        # 5 Auto-Export if requested
        if args.export:
            if not cves:
                self.console.print("[yellow]Nothing to export.[/yellow]")
                return

            if args.index:
                try:
                    indices_to_export = [int(x.strip()) for x in args.index.split(',') if x.strip().isdigit()]
                    self.console.print(f"\n[bold cyan]Exporting {len(indices_to_export)} selected item(s)...[/bold cyan]")
                    
                    for idx in indices_to_export:
                        list_idx = idx - 1
                        if 0 <= list_idx < len(cves):
                            self.export_cve_to_markdown(cves[list_idx])
                        else:
                            self.console.print(f"[red]Warning: Index {idx} does not exist in results.[/red]")
                except Exception as e:
                    self.console.print(f"[red]Error parsing index: {e}[/red]")
            else:
                # Export ALL
                self.console.print(f"\n[bold cyan]Exporting ALL ({len(cves)} items)...[/bold cyan]")
                for cve_item in cves:
                    self.export_cve_to_markdown(cve_item)


def main():
    parser = argparse.ArgumentParser(description="Argus CVE - Vulnerability Research Tool")
    
    # CLI Arguments
    parser.add_argument("-k", "--keyword", type=str, help="Search keyword (e.g., 'wordpress', 'apache')")
    parser.add_argument("-d", "--days", type=int, default=7, help="Search range in days (default: 7)")
    parser.add_argument("-s", "--severity", type=str, help="Severities: 1=Critical, 2=High, 3=Medium, 4=Low. Ex: '1,2'")
    parser.add_argument("-e", "--export", action="store_true", help="Enable export mode")
    parser.add_argument("-i", "--index", type=str, help="Specific ID(s) to export (e.g. '1' or '1,3'). Use with -e.")
    parser.add_argument("-l", "--limit", type=int, help="Limit max results (default: None/All)")

    # Check if any argument passed (except script name)
    if len(sys.argv) > 1:
        args = parser.parse_args()
        app = CVEAnalyzer()
        try:
            app.run_cli_search(args)
        except KeyboardInterrupt:
            print("\nInterrupted.")
    else:
        # Interactive Mode
        app = CVEAnalyzer()
        try:
            app.show_main_menu()
        except KeyboardInterrupt:
            print("\nBye!")
        except Exception as e:
            print(f"Fatal error: {e}")

if __name__ == "__main__":
    main()