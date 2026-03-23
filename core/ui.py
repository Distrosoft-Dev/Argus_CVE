import os
from typing import List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import IntPrompt
from rich import box
from core.models import CVEDetails

def clear_screen():
    """Nettoie le terminal."""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_severity_styled(severity: str) -> str:
    """Retourne la sévérité avec le bon code couleur Rich."""
    colors = {
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[red]HIGH[/red]",
        "MEDIUM": "[yellow]MEDIUM[/yellow]",
        "LOW": "[green]LOW[/green]",
        "N/A": "[dim]N/A[/dim]"
    }
    return colors.get(severity, severity)

def show_main_menu_header(console: Console, cisa_count: int, has_api_key: bool):
    """Affiche la bannière d'accueil et le statut des dépendances."""
    ascii_art = """[bold cyan]
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗     ██████╗██╗   ██╗███████╗       
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝    ██╔════╝██║   ██║██╔════╝       
███████║██████╔╝██║  ███╗██║   ██║███████╗    ██║     ██║   ██║█████╗         
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║    ██║     ╚██╗ ██╔╝██╔══╝         
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║    ╚██████╗ ╚████╔╝ ███████╗       
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝     ╚═════╝  ╚═══╝  ╚══════╝       
[/bold cyan]"""
    console.print(ascii_art)
    
    if cisa_count > 0:
        console.print(f"[bold green]✓ CISA KEV Database loaded ({cisa_count} entries)[/bold green]", justify="center")
    else:
        console.print("[dim]! CISA Database not loaded (offline mode or error)[/dim]", justify="center")
    
    if has_api_key:
        console.print("[bold green]✓ API Key Detected (Fast Mode)[/bold green]", justify="center")
    else:
        console.print("[dim]! No API Key (Slow Mode)[/dim]", justify="center")

    console.print(Panel.fit("[bold]Argus CVE[/bold]", title="Made by DistroSoft", border_style="cyan"))

def display_cves_table(console: Console, cves: List[CVEDetails], page: int = 1, per_page: int = 20) -> int:
    """Affiche la liste des CVEs sous forme de tableau paginé."""
    if not cves:
        console.print(Panel("[italic yellow]No CVEs found.[/italic yellow]", title="Results"))
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

    for i, cve in enumerate(page_cves, start=start_idx + 1):
        score_style = "green"
        if cve.numeric_score >= 9.0: score_style = "bold red"
        elif cve.numeric_score >= 7.0: score_style = "red"
        elif cve.numeric_score >= 4.0: score_style = "yellow"
        
        poc_style = "dim"
        if "ACTIVE" in cve.poc_status: poc_style = "bold red blink"
        elif "Yes" in cve.poc_status: poc_style = "bold yellow"

        short_desc = (cve.description[:60] + "...") if len(cve.description) > 60 else cve.description

        table.add_row(
            str(i),
            f"{cve.id}\n[dim]{cve.published}[/dim]",
            f"[{score_style}]{cve.score}[/{score_style}]",
            get_severity_styled(cve.severity),
            f"[{poc_style}]{cve.poc_status}[/{poc_style}]",
            short_desc
        )

    console.print(table)
    return len(page_cves)

def display_detailed_cve(console: Console, cve: CVEDetails):
    """Affiche le panneau de détails d'une CVE spécifique."""
    clear_screen()
    panel_text = f"""
[bold cyan]ID:[/bold cyan] {cve.id}
[bold cyan]CVSS:[/bold cyan] {cve.score} ({cve.severity})
[bold cyan]Vector:[/bold cyan] {cve.vector}
[bold cyan]CWE:[/bold cyan] {cve.cwe}
[bold cyan]POC Status:[/bold cyan] {cve.poc_status}

[bold]Description:[/bold]
{cve.description}
"""
    title_style = "bold red" if cve.is_critical else "bold blue"
    console.print(Panel(panel_text, title=f"Details - {cve.id}", border_style=title_style))
    
    if cve.exploit_refs:
        console.print("[bold yellow]Potential exploit links found! See Markdown export.[/bold yellow]")
