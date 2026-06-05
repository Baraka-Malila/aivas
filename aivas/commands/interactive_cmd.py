import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.text import Text

from aivas import config as _config

console = Console()

_BANNER = """[bold cyan]
   █████╗ ██╗██╗   ██╗ █████╗ ███████╗
  ██╔══██╗██║██║   ██║██╔══██╗██╔════╝
  ███████║██║██║   ██║███████║███████╗
  ██╔══██║██║╚██╗ ██╔╝██╔══██║╚════██║
  ██║  ██║██║ ╚████╔╝ ██║  ██║███████║
  ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝[/bold cyan]
[dim]  AI-Assisted Vulnerability Assessment System[/dim]
[dim]  Type Ctrl+C at any time to exit.[/dim]"""


def _pick_level() -> int:
    console.print(
        "  [dim]1[/dim] Quick  — service detection only\n"
        "  [dim]2[/dim] Full   — CVE sweep + config probes  [bold](recommended)[/bold]\n"
        "  [dim]3[/dim] Deep   — + SSH package scan"
    )
    choice = Prompt.ask("  Scan level", choices=["1", "2", "3"], default="2")
    return int(choice)


@click.command("interactive")
@click.pass_context
def interactive(ctx: click.Context) -> None:
    """Launch guided interactive scan mode."""
    cfg = _config.load()

    console.print(Panel(Text.from_markup(_BANNER), border_style="cyan", padding=(0, 2)))

    while True:
        console.print()
        target = Prompt.ask("[bold]  Target[/bold] (IP, range, or hostname)").strip()
        if not target:
            console.print("[yellow]  No target entered.[/yellow]")
            continue

        level = _pick_level()
        udp = Confirm.ask("  Include UDP scan?", default=False)
        narrate = Confirm.ask("  Generate AI risk narration?",
                              default=cfg.get("narrate", False))
        save = Confirm.ask("  Save findings to history?", default=False)

        console.print()
        console.print(Panel(
            Text.from_markup(
                f"  [bold]Scan plan:[/bold] {target} --level {level}\n"
                + (f"  [dim]Focus:[/dim] {'UDP enabled' if udp else 'TCP only'}")
            ),
            border_style="dim",
            padding=(0, 2),
        ))

        if not Confirm.ask("  Proceed?", default=True):
            continue

        from aivas.commands.scan_cmd import scan as _scan
        try:
            ctx.invoke(
                _scan,
                target=target,
                import_file=None,
                level=level,
                limit=30,
                min_confidence="probable",
                narrate=narrate,
                lang=cfg.get("lang", "both"),
                provider=cfg.get("provider", "groq"),
                api_key=cfg.get("api_key"),
                report_path=None,
                save=save,
                udp=udp,
                credentials=None,
            )
        except click.ClickException as exc:
            console.print(f"[red]Error:[/red] {exc.format_message()}")
        except Exception as exc:
            console.print(f"[red]Unexpected error:[/red] {exc}")

        console.print()
        if not Confirm.ask("  Scan another target?", default=True):
            break

    console.print("\n[dim]Session ended.[/dim]")
