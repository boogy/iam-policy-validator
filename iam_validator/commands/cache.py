"""Cache management command for IAM Policy Validator."""

import argparse
import logging
from pathlib import Path

from rich.console import Console
from rich.table import Table

from iam_validator.commands.base import Command
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.aws_service.storage import ServiceFileStorage
from iam_validator.core.config.config_loader import ConfigLoader

logger = logging.getLogger(__name__)
console = Console()


class CacheCommand(Command):
    """Manage AWS service definition cache."""

    @property
    def name(self) -> str:
        return "cache"

    @property
    def help(self) -> str:
        return "Manage AWS service definition cache"

    @property
    def epilog(self) -> str:
        return """
Examples:
  # Show cache information
  iam-validator cache info

  # List all cached services
  iam-validator cache list

  # Clear all cached AWS service definitions
  iam-validator cache clear

  # Refresh all cached services with fresh data
  iam-validator cache refresh

  # Pre-fetch common AWS services
  iam-validator cache prefetch

  # Show cache location
  iam-validator cache location
"""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add cache command arguments."""
        subparsers = parser.add_subparsers(dest="cache_action", help="Cache action to perform")

        # Info subcommand
        info_parser = subparsers.add_parser("info", help="Show cache information and statistics")
        info_parser.add_argument(
            "--config",
            type=str,
            help="Path to configuration file",
        )

        # List subcommand
        list_parser = subparsers.add_parser("list", help="List all cached AWS services")
        list_parser.add_argument(
            "--config",
            type=str,
            help="Path to configuration file",
        )
        list_parser.add_argument(
            "--format",
            choices=["table", "columns", "simple"],
            default="table",
            help="Output format (default: table)",
        )

        # Clear subcommand
        clear_parser = subparsers.add_parser(
            "clear", help="Clear all cached AWS service definitions"
        )
        clear_parser.add_argument(
            "--config",
            type=str,
            help="Path to configuration file",
        )

        # Refresh subcommand
        refresh_parser = subparsers.add_parser(
            "refresh", help="Refresh all cached AWS services with fresh data"
        )
        refresh_parser.add_argument(
            "--config",
            type=str,
            help="Path to configuration file",
        )

        # Prefetch subcommand
        prefetch_parser = subparsers.add_parser(
            "prefetch", help="Pre-fetch common AWS services (without clearing)"
        )
        prefetch_parser.add_argument(
            "--config",
            type=str,
            help="Path to configuration file",
        )

        # Location subcommand
        location_parser = subparsers.add_parser("location", help="Show cache directory location")
        location_parser.add_argument(
            "--config",
            type=str,
            help="Path to configuration file",
        )

    async def execute(self, args: argparse.Namespace) -> int:
        """Execute cache command."""
        if not hasattr(args, "cache_action") or not args.cache_action:
            console.print("[red]Error:[/red] No cache action specified")
            console.print("Use 'iam-validator cache --help' for available actions")
            return 1

        # Load config to get cache settings
        config_path = getattr(args, "config", None)
        config = ConfigLoader.load_config(explicit_path=config_path, allow_missing=True)

        cache_enabled = config.get_setting("cache_enabled", True)
        cache_ttl_hours = config.get_setting("cache_ttl_hours", 168)
        cache_directory = config.get_setting("cache_directory", None)
        cache_ttl_seconds = cache_ttl_hours * 3600

        # Get cache directory (even if caching is disabled, for info purposes)
        cache_dir = ServiceFileStorage.get_cache_directory(cache_directory)

        action = args.cache_action

        if action == "info":
            return await self._show_info(cache_dir, cache_enabled, cache_ttl_hours)
        elif action == "list":
            output_format = getattr(args, "format", "table")
            return self._list_cached_services(cache_dir, output_format)
        elif action == "clear":
            return await self._clear_cache(cache_dir, cache_enabled)
        elif action == "refresh":
            return await self._refresh_cache(cache_enabled, cache_ttl_seconds, cache_directory)
        elif action == "prefetch":
            return await self._prefetch_services(cache_enabled, cache_ttl_seconds, cache_directory)
        elif action == "location":
            return self._show_location(cache_dir)
        else:
            console.print(f"[red]Error:[/red] Unknown cache action: {action}")
            return 1

    async def _show_info(self, cache_dir: Path, cache_enabled: bool, cache_ttl_hours: int) -> int:
        """Show cache information and statistics."""
        table = Table(title="Cache Information")
        table.add_column("Setting", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        # Cache status
        table.add_row(
            "Status", "[green]Enabled[/green]" if cache_enabled else "[red]Disabled[/red]"
        )

        # Cache location
        table.add_row("Location", str(cache_dir))

        # Cache exists?
        exists = cache_dir.exists()
        table.add_row("Exists", "[green]Yes[/green]" if exists else "[yellow]No[/yellow]")

        # Cache TTL
        ttl_days = cache_ttl_hours / 24
        table.add_row("TTL", f"{cache_ttl_hours} hours ({ttl_days:.1f} days)")

        if exists:
            # Count cached files
            cache_files = list(cache_dir.glob("*.json"))
            table.add_row("Cached Services", str(len(cache_files)))

            # Calculate cache size
            total_size = sum(f.stat().st_size for f in cache_files)
            size_mb = total_size / (1024 * 1024)
            table.add_row("Cache Size", f"{size_mb:.2f} MB")

            # Show some cached services
            if cache_files:
                service_names = []
                for f in cache_files[:5]:
                    name = f.stem.split("_")[0] if "_" in f.stem else f.stem
                    service_names.append(name)
                sample = ", ".join(service_names)
                if len(cache_files) > 5:
                    sample += f", ... ({len(cache_files) - 5} more)"
                table.add_row("Sample Services", sample)

        console.print(table)
        return 0

    def _list_cached_services(self, cache_dir: Path, output_format: str) -> int:
        """List all cached AWS services."""
        if not cache_dir.exists():
            console.print("[yellow]Cache directory does not exist[/yellow]")
            return 0

        cache_files = list(cache_dir.glob("*.json"))

        if not cache_files:
            console.print("[yellow]No services cached yet[/yellow]")
            return 0

        # Extract service names from filenames
        services = []
        for f in cache_files:
            # Handle both formats: "service_hash.json" and "services_list.json"
            if f.stem == "services_list":
                continue  # Skip the services list file

            # Extract service name (before underscore or full name)
            name = f.stem.split("_")[0] if "_" in f.stem else f.stem

            # Get file stats
            size = f.stat().st_size
            mtime = f.stat().st_mtime

            services.append({"name": name, "size": size, "file": f.name, "mtime": mtime})

        # Sort by service name
        services.sort(key=lambda x: str(x["name"]))

        if output_format == "table":
            self._print_services_table(services)
        elif output_format == "columns":
            self._print_services_columns(services)
        else:  # simple
            self._print_services_simple(services)

        return 0

    def _print_services_table(self, services: list[dict]) -> None:
        """Print services in a nice table format."""
        from datetime import datetime

        table = Table(title=f"Cached AWS Services ({len(services)} total)")
        table.add_column("Service", style="cyan", no_wrap=True)
        table.add_column("Cache File", style="white")
        table.add_column("Size", style="yellow", justify="right")
        table.add_column("Cached", style="green")

        for svc in services:
            size_kb = svc["size"] / 1024
            cached_time = datetime.fromtimestamp(svc["mtime"]).strftime("%Y-%m-%d %H:%M")

            table.add_row(svc["name"], svc["file"], f"{size_kb:.1f} KB", cached_time)

        console.print(table)

    def _print_services_columns(self, services: list[dict]) -> None:
        """Print services in columns format (like ls)."""
        from rich.columns import Columns

        console.print(f"[cyan]Cached AWS Services ({len(services)} total):[/cyan]\n")

        service_names = [f"[green]{svc['name']}[/green]" for svc in services]
        console.print(Columns(service_names, equal=True, expand=False))

    def _print_services_simple(self, services: list[dict]) -> None:
        """Print services in simple list format."""
        console.print(f"[cyan]Cached AWS Services ({len(services)} total):[/cyan]\n")

        for svc in services:
            console.print(svc["name"])

    async def _clear_cache(self, cache_dir: Path, cache_enabled: bool) -> int:
        """Clear all cached AWS service definitions."""
        if not cache_enabled:
            console.print("[yellow]Warning:[/yellow] Cache is disabled in config")
            return 0

        if not cache_dir.exists():
            console.print("[yellow]Cache directory does not exist, nothing to clear[/yellow]")
            return 0

        # Count files before deletion
        cache_files = list(cache_dir.glob("*.json"))
        file_count = len(cache_files)

        if file_count == 0:
            console.print("[yellow]Cache is already empty[/yellow]")
            return 0

        # Delete cache files
        deleted = 0
        failed = 0
        for cache_file in cache_files:
            try:
                cache_file.unlink()
                deleted += 1
            except Exception as e:
                logger.error(f"Failed to delete {cache_file}: {e}")
                failed += 1

        if failed == 0:
            console.print(f"[green]✓[/green] Cleared {deleted} cached service definitions")
        else:
            console.print(
                f"[yellow]![/yellow] Cleared {deleted} files, failed to delete {failed} files"
            )
            return 1

        return 0

    async def _refresh_cache(
        self, cache_enabled: bool, cache_ttl_seconds: int, cache_directory: str | None
    ) -> int:
        """Refresh all cached services with fresh data from AWS."""
        if not cache_enabled:
            console.print("[red]Error:[/red] Cache is disabled in config")
            console.print("Enable cache by setting 'cache_enabled: true' in your config")
            return 1

        # Get cache directory
        cache_dir = (
            Path(cache_directory) if cache_directory else ServiceFileStorage.get_cache_directory()
        )

        if not cache_dir.exists():
            console.print("[yellow]Cache directory does not exist, nothing to refresh[/yellow]")
            console.print("Run 'iam-validator cache prefetch' to populate the cache first")
            return 0

        # Get list of cached services from cache files
        cache_files = list(cache_dir.glob("*.json"))
        if not cache_files:
            console.print("[yellow]No services cached yet, nothing to refresh[/yellow]")
            console.print("Run 'iam-validator cache prefetch' to populate the cache first")
            return 0

        # Extract service names from cache files
        cached_services: list[str] = []
        for f in cache_files:
            if f.stem == "services_list":
                continue  # Skip the services list file, we'll refresh it separately
            # Extract service name (before underscore or full name)
            name = f.stem.split("_")[0] if "_" in f.stem else f.stem
            cached_services.append(name)

        cached_services.sort()
        console.print(f"[cyan]Refreshing {len(cached_services)} cached services...[/cyan]")

        async with AWSServiceFetcher(
            enable_cache=cache_enabled,
            cache_ttl=cache_ttl_seconds,
            cache_dir=cache_directory,
            prefetch_common=False,  # We'll refresh manually
        ) as fetcher:
            # First refresh the services list
            console.print("Refreshing AWS services list...")
            services = await fetcher.fetch_services()
            console.print(f"[green]✓[/green] Refreshed services list ({len(services)} services)")

            # Build a set of valid service names for validation
            valid_services = {svc.service for svc in services}

            # Refresh each cached service
            console.print(f"Refreshing {len(cached_services)} cached service definitions...")
            refreshed = 0
            failed = 0
            skipped = 0

            for service_name in cached_services:
                # Skip services that no longer exist in AWS
                if service_name not in valid_services:
                    logger.warning(f"Service '{service_name}' no longer exists, skipping")
                    skipped += 1
                    continue

                try:
                    await fetcher.fetch_service_by_name(service_name)
                    refreshed += 1
                except Exception as e:
                    logger.warning(f"Failed to refresh {service_name}: {e}")
                    failed += 1

            # Print summary
            if failed == 0 and skipped == 0:
                console.print(f"[green]✓[/green] Refreshed {refreshed} services successfully")
            else:
                console.print(
                    f"[yellow]![/yellow] Refreshed {refreshed} services, "
                    f"{failed} failed, {skipped} skipped (no longer exist)"
                )

        console.print("[green]✓[/green] Cache refresh complete")
        return 0 if failed == 0 else 1

    async def _prefetch_services(
        self, cache_enabled: bool, cache_ttl_seconds: int, cache_directory: str | None
    ) -> int:
        """Pre-fetch common AWS services without clearing cache."""
        if not cache_enabled:
            console.print("[red]Error:[/red] Cache is disabled in config")
            console.print("Enable cache by setting 'cache_enabled: true' in your config")
            return 1

        console.print("[cyan]Pre-fetching common AWS services...[/cyan]")

        async with AWSServiceFetcher(
            enable_cache=cache_enabled,
            cache_ttl=cache_ttl_seconds,
            cache_dir=cache_directory,
            prefetch_common=True,  # Enable prefetching
        ) as fetcher:
            # Prefetching happens in __aenter__, just wait for it
            prefetched = len(fetcher._prefetched_services)
            total = len(fetcher.COMMON_SERVICES)

            console.print(
                f"[green]✓[/green] Pre-fetched {prefetched}/{total} common services successfully"
            )

        return 0

    def _show_location(self, cache_dir: Path) -> int:
        """Show cache directory location."""
        console.print(f"[cyan]Cache directory:[/cyan] {cache_dir}")

        if cache_dir.exists():
            console.print("[green]✓[/green] Directory exists")
        else:
            console.print("[yellow]![/yellow] Directory does not exist yet")
            console.print("It will be created automatically when caching is used")

        return 0
