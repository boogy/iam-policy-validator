#!/usr/bin/env python3
"""Download all AWS service definition JSON files for backup.

This script downloads the complete AWS service reference data and stores it
locally as a backup to avoid API throttling and enable offline usage.

Usage:
    python scripts/download_aws_services.py [--output-dir PATH]

The script will:
1. Fetch the list of all AWS services from the AWS Service Reference API
2. Download each service's detailed JSON definition
3. Save them to aws_services/ directory
4. Create a manifest file with metadata

Directory structure:
    aws_services/
        _manifest.json  # Metadata about the download (underscore prefix for easy discovery)
        _services.json  # List of all services (underscore prefix for easy discovery)
        s3.json         # Individual service definitions
        ec2.json
        iam.json
        ...
"""

import argparse
import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import httpx

from iam_validator.core.config import AWS_SERVICE_REFERENCE_BASE_URL

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

BASE_URL = AWS_SERVICE_REFERENCE_BASE_URL
DEFAULT_OUTPUT_DIR = Path("aws_services")


async def download_services_list(client: httpx.AsyncClient) -> list[dict]:
    """Download the list of all AWS services.

    Args:
        client: HTTP client for making requests

    Returns:
        List of service info dictionaries
    """
    logger.info(f"Fetching services list from {BASE_URL}")

    try:
        response = await client.get(BASE_URL, timeout=30.0)
        response.raise_for_status()
        services = response.json()

        logger.info(f"Found {len(services)} AWS services")
        return services
    except Exception as e:
        logger.error(f"Failed to fetch services list: {e}")
        raise


async def download_service_detail(
    client: httpx.AsyncClient,
    service_name: str,
    service_url: str,
    semaphore: asyncio.Semaphore,
) -> tuple[str, dict | None]:
    """Download detailed JSON for a single service.

    Args:
        client: HTTP client for making requests
        service_name: Name of the service
        service_url: URL to fetch service details
        semaphore: Semaphore to limit concurrent requests

    Returns:
        Tuple of (service_name, service_data) or (service_name, None) if failed
    """
    async with semaphore:
        try:
            logger.info(f"Downloading {service_name}...")
            response = await client.get(service_url, timeout=30.0)
            response.raise_for_status()
            data = response.json()
            logger.info(f"✓ Downloaded {service_name}")
            return service_name, data
        except Exception as e:
            logger.error(f"✗ Failed to download {service_name}: {e}")
            return service_name, None


async def download_all_services(output_dir: Path, max_concurrent: int = 10) -> None:
    """Download all AWS service definitions.

    Args:
        output_dir: Directory to save the downloaded files
        max_concurrent: Maximum number of concurrent downloads
    """
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create HTTP client with connection pooling
    async with httpx.AsyncClient(
        limits=httpx.Limits(max_connections=max_concurrent, max_keepalive_connections=5),
        timeout=httpx.Timeout(30.0),
    ) as client:
        # Download services list
        services = await download_services_list(client)

        # Save services list (underscore prefix for easy discovery at top of directory)
        services_file = output_dir / "_services.json"
        with open(services_file, "w") as f:
            json.dump(services, f, indent=2)
        logger.info(f"Saved services list to {services_file}")

        # Download all service details with rate limiting
        semaphore = asyncio.Semaphore(max_concurrent)
        tasks = []

        for item in services:
            service_name = item.get("service")
            service_url = item.get("url")

            if service_name and service_url:
                task = download_service_detail(client, service_name, service_url, semaphore)
                tasks.append(task)

        # Download all services concurrently
        logger.info(f"\nDownloading {len(tasks)} service definitions...")
        results = await asyncio.gather(*tasks)

        # Save individual service files
        successful = 0
        failed = 0

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

        logger.info(f"\n{'=' * 60}")
        logger.info("Download Summary:")
        logger.info(f"  Total services: {len(services)}")
        logger.info(f"  Successful: {successful}")
        logger.info(f"  Failed: {failed}")
        logger.info(f"  Output directory: {output_dir.absolute()}")
        logger.info(f"  Manifest: {manifest_file}")
        logger.info(f"{'=' * 60}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Download all AWS service definition JSON files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

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

    args = parser.parse_args()

    try:
        asyncio.run(download_all_services(args.output_dir, args.max_concurrent))
    except KeyboardInterrupt:
        logger.warning("\nDownload interrupted by user")
    except Exception as e:
        logger.error(f"Download failed: {e}")
        raise


if __name__ == "__main__":
    main()
