"""Download AWS service definitions command."""

import argparse
import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import httpx
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskID, TextColumn, TimeRemainingColumn

from iam_validator.commands.base import Command
from iam_validator.core.config import AWS_SERVICE_REFERENCE_BASE_URL

logger = logging.getLogger(__name__)
console = Console()

BASE_URL = AWS_SERVICE_REFERENCE_BASE_URL
DEFAULT_OUTPUT_DIR = Path("aws_services")


class DownloadServicesCommand(Command):
    """Download all AWS service definition JSON files."""

    @property
    def name(self) -> str:
        return "sync-services"

    @property
    def help(self) -> str:
        return "Sync/download all AWS service definitions for offline use"

    @property
    def epilog(self) -> str:
        return """
Examples:
  # Sync all AWS service definitions to default directory (aws_services/)
  iam-validator sync-services

  # Sync to a custom directory
  iam-validator sync-services --output-dir /path/to/backup

  # Limit concurrent downloads
  iam-validator sync-services --max-concurrent 5

  # Enable verbose output
  iam-validator sync-services --log-level debug

Directory structure:
  aws_services/
      _manifest.json         # Metadata about the download
      _services.json         # List of all services
      s3.json                # Individual service definitions
      ec2.json
      iam.json
      ...

This command is useful for:
  - Creating offline backups of AWS service definitions
  - Avoiding API rate limiting during development
  - Ensuring consistent service definitions across environments
"""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add sync-services command arguments."""
        parser.add_argument(
            "--output-dir",
            type=Path,
            default=DEFAULT_OUTPUT_DIR,
            help=f"Output directory for downloaded files (default: {DEFAULT_OUTPUT_DIR})",
        )

        parser.add_argument(
            "--max-concurrent",
            type=int,
            default=10,
            help="Maximum number of concurrent downloads (default: 10)",
        )

    async def execute(self, args: argparse.Namespace) -> int:
        """Execute the sync-services command."""
        output_dir = args.output_dir
        max_concurrent = args.max_concurrent

        try:
            await self._download_all_services(output_dir, max_concurrent)
            return 0
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            logger.error(f"Download failed: {e}", exc_info=True)
            return 1

    async def _download_services_list(self, client: httpx.AsyncClient) -> list[dict]:
        """Download the list of all AWS services.

        Args:
            client: HTTP client for making requests

        Returns:
            List of service info dictionaries
        """
        console.print(f"[cyan]Fetching services list from {BASE_URL}...[/cyan]")

        try:
            response = await client.get(BASE_URL, timeout=30.0)
            response.raise_for_status()
            services = response.json()

            console.print(f"[green]✓[/green] Found {len(services)} AWS services")
            return services
        except Exception as e:
            logger.error(f"Failed to fetch services list: {e}")
            raise

    async def _download_service_detail(
        self,
        client: httpx.AsyncClient,
        service_name: str,
        service_url: str,
        semaphore: asyncio.Semaphore,
        progress: Progress,
        task_id: TaskID,
    ) -> tuple[str, dict | None]:
        """Download detailed JSON for a single service.

        Args:
            client: HTTP client for making requests
            service_name: Name of the service
            service_url: URL to fetch service details
            semaphore: Semaphore to limit concurrent requests
            progress: Progress bar instance
            task_id: Progress task ID

        Returns:
            Tuple of (service_name, service_data) or (service_name, None) if failed
        """
        async with semaphore:
            try:
                logger.debug(f"Downloading {service_name}...")
                response = await client.get(service_url, timeout=30.0)
                response.raise_for_status()
                data = response.json()
                logger.debug(f"✓ Downloaded {service_name}")
                progress.update(task_id, advance=1)
                return service_name, data
            except Exception as e:
                logger.error(f"✗ Failed to download {service_name}: {e}")
                progress.update(task_id, advance=1)
                return service_name, None

    async def _download_all_services(self, output_dir: Path, max_concurrent: int = 10) -> None:
        """Download all AWS service definitions.

        Args:
            output_dir: Directory to save the downloaded files
            max_concurrent: Maximum number of concurrent downloads
        """
        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)
        console.print(f"[cyan]Output directory:[/cyan] {output_dir.absolute()}\n")

        # Create HTTP client with connection pooling
        async with httpx.AsyncClient(
            limits=httpx.Limits(max_connections=max_concurrent, max_keepalive_connections=5),
            timeout=httpx.Timeout(30.0),
        ) as client:
            # Download services list
            services = await self._download_services_list(client)

            # Save services list (underscore prefix for easy discovery at top of directory)
            services_file = output_dir / "_services.json"
            with open(services_file, "w") as f:
                json.dump(services, f, indent=2)
            console.print(f"[green]✓[/green] Saved services list to {services_file}\n")

            # Download all service details with rate limiting and progress bar
            semaphore = asyncio.Semaphore(max_concurrent)
            tasks = []

            # Set up progress bar
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task_id = progress.add_task(
                    "[cyan]Downloading service definitions...", total=len(services)
                )

                for item in services:
                    service_name = item.get("service")
                    service_url = item.get("url")

                    if service_name and service_url:
                        task = self._download_service_detail(
                            client, service_name, service_url, semaphore, progress, task_id
                        )
                        tasks.append(task)

                # Download all services concurrently
                results = await asyncio.gather(*tasks)

            # Save individual service files
            successful = 0
            failed = 0

            console.print("\n[cyan]Saving service definitions...[/cyan]")

            for service_name, data in results:
                if data is not None:
                    # Normalize filename (lowercase, safe characters)
                    filename = f"{service_name.lower().replace(' ', '_')}.json"
                    service_file = output_dir / filename

                    with open(service_file, "w") as f:
                        json.dump(data, f, indent=2)

                    successful += 1
                else:
                    failed += 1

            # Create manifest with metadata
            manifest = {
                "download_date": datetime.now(timezone.utc).isoformat(),
                "total_services": len(services),
                "successful_downloads": successful,
                "failed_downloads": failed,
                "base_url": BASE_URL,
            }

            manifest_file = output_dir / "_manifest.json"
            with open(manifest_file, "w") as f:
                json.dump(manifest, f, indent=2)

            # Print summary
            console.print(f"\n{'=' * 60}")
            console.print("[bold cyan]Download Summary:[/bold cyan]")
            console.print(f"  Total services: {len(services)}")
            console.print(f"  [green]Successful:[/green] {successful}")
            if failed > 0:
                console.print(f"  [red]Failed:[/red] {failed}")
            console.print(f"  Output directory: {output_dir.absolute()}")
            console.print(f"  Manifest: {manifest_file}")
            console.print(f"{'=' * 60}")

            if failed > 0:
                console.print(
                    "\n[yellow]Warning:[/yellow] Some services failed to download. "
                    "Check the logs for details."
                )
