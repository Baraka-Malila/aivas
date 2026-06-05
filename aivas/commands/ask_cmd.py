"""ask command — describe a scan in plain English and AIVAS will run it."""

import click
from rich.console import Console

from aivas.narrator.intent import parse_intent
from aivas.narrator.providers import get_provider

console = Console()


@click.command()
@click.argument("query")
@click.option(
    "--provider", default="groq",
    type=click.Choice(["groq", "ollama"]),
    show_default=True,
    help="LLM provider used to interpret the query.",
)
@click.option(
    "--api-key", "api_key", default=None, envvar="GROQ_API_KEY",
    help="Groq API key (or set GROQ_API_KEY).",
)
@click.pass_context
def ask(ctx: click.Context, query: str, provider: str, api_key: str | None) -> None:
    """Describe a scan in plain English — AIVAS will interpret and run it."""
    # 1. Resolve LLM provider
    try:
        llm = get_provider(provider, api_key=api_key)
    except ValueError as exc:
        raise click.ClickException(str(exc))

    # 2. Parse natural language intent
    try:
        with console.status("Interpreting..."):
            intent = parse_intent(query, llm)
    except ValueError as exc:
        raise click.ClickException(str(exc))

    target = intent.get("target")
    level = intent.get("level") or 2
    focus = intent.get("focus")

    # 3. Validate target
    if not target:
        raise click.ClickException("Could not identify a scan target.")

    # 4. Show scan plan
    console.print(f"[bold]Scan plan:[/bold] {target} --level {level}")
    if focus:
        console.print(f"[dim]Focus: {focus}[/dim]")

    # 5. Confirm with user
    if not click.confirm("Proceed?", default=False):
        click.echo("Scan cancelled.")
        return

    # 6. Invoke scan command
    from aivas.commands.scan_cmd import scan as _scan_cmd
    ctx.invoke(
        _scan_cmd,
        target=target,
        level=level,
        import_file=None,
        limit=30,
        min_confidence="probable",
        narrate=False,
        lang="both",
        provider=provider,
        api_key=api_key,
        report_path=None,
        save=False,
        udp=False,
        credentials=None,
    )
