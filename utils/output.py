from rich.console import Console
from rich.theme import Theme

custom_theme = Theme({
    "info":    "cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "danger":  "bold red",
    "muted":   "dim white",
    "header":  "bold magenta",
})

console = Console(theme=custom_theme)

def banner(title: str, version: str = "1.0"):
    console.print(f"\n[header]{'='*50}[/header]")
    console.print(f"[header]  {title} v{version}[/header]")
    console.print(f"[header]  sec-toolkit | for authorised use only[/header]")
    console.print(f"[header]{'='*50}[/header]\n")

def info(msg):    console.print(f"[info][*][/info] {msg}")
def success(msg): console.print(f"[success][+][/success] {msg}")
def warning(msg): console.print(f"[warning][!][/warning] {msg}")
def error(msg):   console.print(f"[danger][-][/danger] {msg}")
def muted(msg):   console.print(f"[muted]{msg}[/muted]")