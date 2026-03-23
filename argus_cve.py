import sys
import argparse
from datetime import datetime, timedelta, timezone
from rich.console import Console
from rich.prompt import IntPrompt, Prompt
from rich.panel import Panel

# Importation de tes modules séparés
from core.api_client import NVDClient
from core.models import parse_cve_item, CVEDetails
from core.exporter import init_folders, save_cve_json, export_cve_markdown
from core import ui

# Constantes de configuration globale
MAX_DATE_RANGE_DAYS = 110
RESULTS_PER_PAGE = 20

class ArgusApp:
    def __init__(self):
        self.console = Console()
        self.api = NVDClient()
        init_folders()
        
        # Chargement initial CISA
        with self.console.status("[dim]Loading CISA KEV Database...[/dim]"):
            success, error_msg = self.api.load_cisa_kev()
            if not success:
                self.console.print(f"[yellow]Warning: {error_msg}[/yellow]")

    def fetch_cves_orchestrator(self, start_date: datetime, end_date: datetime, keyword: str = None, severities: list = None, limit: int = None):
        """Orchestre les appels API en découpant les dates si nécessaire, puis parse les résultats."""
        base_params = {}
        if keyword: base_params["keywordSearch"] = keyword
        if limit: base_params["resultsPerPage"] = limit
        
        target_severities = [s.upper() for s in severities if s] if severities else []
        filter_severity_locally = False
        
        if len(target_severities) == 1:
            base_params["cvssV3Severity"] = target_severities[0]
        elif len(target_severities) > 1:
            filter_severity_locally = True

        delta = end_date - start_date
        ranges = []
        current_start = start_date
        
        while current_start < end_date:
            current_end = current_start + timedelta(days=MAX_DATE_RANGE_DAYS)
            if current_end > end_date: current_end = end_date
            ranges.append((current_start, current_end))
            current_start = current_end

        if delta.days > MAX_DATE_RANGE_DAYS:
            self.console.print(f"[yellow]Date range ({delta.days} days) exceeds NVD limit. Splitting into {len(ranges)} chunks...[/yellow]")

        all_raw_vulns = []
        for r_start, r_end in ranges:
            s_str = r_start.strftime("%Y-%m-%dT%H:%M:%S.000")
            e_str = r_end.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            params = base_params.copy()
            params["pubStartDate"] = s_str
            params["pubEndDate"] = e_str
            
            if delta.days > MAX_DATE_RANGE_DAYS:
                self.console.print(f"   [dim]Fetching {s_str[:10]} -> {e_str[:10]}...[/dim]")
                
            vulns, _, _ = self.api.fetch_nvd_page(params)
            all_raw_vulns.extend(vulns)

        # Parsing via notre dataclass Model
        parsed_cves = []
        for v in all_raw_vulns:
            cve_id = v.get("cve", {}).get("id")
            is_in_kev = self.api.is_cve_in_kev(cve_id)
            parsed_cve = parse_cve_item(v, is_in_kev)
            
            # Filtre local si plusieurs sévérités sélectionnées
            if filter_severity_locally and parsed_cve.severity not in target_severities:
                continue
                
            parsed_cves.append(parsed_cve)

        # Tri par score (via la property numeric_score de notre modèle) puis date
        parsed_cves.sort(key=lambda x: (x.numeric_score, x.published), reverse=True)
        return parsed_cves

    def interactive_search(self):
        ui.clear_screen()
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

        with self.console.status("[bold green]Querying NIST (this might take time)...[/bold green]"):
            cves = self.fetch_cves_orchestrator(start_date, end_date, keyword, selected_severities)

        self.console.print(f"[bold green]{len(cves)} vulnerabilities found.[/bold green]")
        
        current_page = 1
        while True:
            count = ui.display_cves_table(self.console, cves, page=current_page, per_page=RESULTS_PER_PAGE)
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
                    selected_cve = cves[idx-1]
                    ui.display_detailed_cve(self.console, selected_cve)
                    
                    self.console.print("\n[bold]Options:[/bold]\n[1] Save (JSON)\n[2] Export Report (Markdown + POCs)\n[0] Return")
                    sub_choice = IntPrompt.ask("Choice", default=0)
                    if sub_choice == 1:
                        path = save_cve_json(selected_cve)
                        self.console.print(f"[bold green]JSON saved: {path}[/bold green]")
                    elif sub_choice == 2:
                        path = export_cve_markdown(selected_cve)
                        self.console.print(f"[bold green]Markdown report exported: {path}[/bold green]")
                        
                    input("\nEnter to continue...")

    def run_interactive_menu(self):
        while True:
            ui.clear_screen()
            ui.show_main_menu_header(self.console, len(self.api.cisa_kev_set), bool(self.api.api_key))
            self.console.print("[1] Search Vulnerabilities\n[0] Exit")
            
            choice = IntPrompt.ask(">", default=0)
            if choice == 0: break
            elif choice == 1: self.interactive_search()

def main():
    parser = argparse.ArgumentParser(description="Argus CVE - Vulnerability Research Tool")
    parser.add_argument("-k", "--keyword", type=str, help="Search keyword (e.g., 'wordpress')")
    parser.add_argument("-d", "--days", type=int, default=7, help="Search range in days")
    parser.add_argument("-s", "--severity", type=str, help="Severities: 1=Critical, 2=High, 3=Medium, 4=Low. Ex: '1,2'")
    parser.add_argument("-e", "--export", action="store_true", help="Enable export mode")
    parser.add_argument("-l", "--limit", type=int, help="Limit max results")

    try:
        app = ArgusApp()
        
        # Mode CLI
        if len(sys.argv) > 1:
            args = parser.parse_args()
            
            severity_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
            selected_severities = []
            if args.severity:
                indices = [int(x.strip()) for x in args.severity.split(',') if x.strip().isdigit()]
                selected_severities = [severity_map[idx] for idx in indices if idx in severity_map]

            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=args.days)
            
            app.console.print(f"[bold]Argus CVE CLI[/bold] | keyword='{args.keyword}' | days={args.days} | severities={selected_severities}")
            
            with app.console.status("[bold green]Fetching data...[/bold green]"):
                cves = app.fetch_cves_orchestrator(start_date, end_date, args.keyword, selected_severities, args.limit)
                
            app.console.print(f"[bold green]{len(cves)} found.[/bold green]")
            ui.display_cves_table(app.console, cves, page=1, per_page=100)
            
            if args.export and cves:
                app.console.print(f"\n[bold cyan]Exporting ALL ({len(cves)} items)...[/bold cyan]")
                for cve in cves:
                    export_cve_markdown(cve)
        
        # Mode Interactif
        else:
            app.run_interactive_menu()
            
    except KeyboardInterrupt:
        print("\nInterrupted by user. Bye!")
    except Exception as e:
        print(f"\nFatal error: {e}")

if __name__ == "__main__":
    main()
