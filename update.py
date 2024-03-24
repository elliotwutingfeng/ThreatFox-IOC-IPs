import asyncio
import csv
import io
import ipaddress
import logging
import socket
import zipfile
import datetime

import aiohttp

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format="%(message)s")

default_headers: dict = {
    "Content-Type": "application/json",
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
    "Accept": "*/*",
}


async def backoff_delay_async(backoff_factor: float, number_of_retries_made: int) -> None:
    """Asynchronous time delay that exponentially increases with `number_of_retries_made`

    Args:
        backoff_factor (float): Backoff delay multiplier
        number_of_retries_made (int): More retries made -> Longer backoff delay
    """
    await asyncio.sleep(backoff_factor * (2 ** (number_of_retries_made - 1)))


async def get_async(
    endpoints: list[str], max_concurrent_requests: int = 5, headers: dict = None
) -> dict[str, bytes]:
    """Given a list of HTTP endpoints, make HTTP GET requests asynchronously

    Args:
        endpoints (list[str]): List of HTTP GET request endpoints
        max_concurrent_requests (int, optional): Maximum number of concurrent async HTTP requests.
        Defaults to 5.
        headers (dict, optional): HTTP Headers to send with every request. Defaults to None.

    Returns:
        dict[str,bytes]: Mapping of HTTP GET request endpoint to its HTTP response content. If
        the GET request failed, its HTTP response content will be `b"{}"`
    """
    if headers is None:
        headers = default_headers

    async def gather_with_concurrency(max_concurrent_requests: int, *tasks) -> dict[str, bytes]:
        semaphore = asyncio.Semaphore(max_concurrent_requests)

        async def sem_task(task):
            async with semaphore:
                await asyncio.sleep(0.5)
                return await task

        tasklist = [sem_task(task) for task in tasks]
        return dict([await f for f in asyncio.as_completed(tasklist)])

    async def get(url, session):
        max_retries: int = 5
        errors: list[str] = []
        for number_of_retries_made in range(max_retries):
            try:
                async with session.get(url, headers=headers) as response:
                    return (url, await response.read())
            except Exception as error:
                errors.append(repr(error))
                logger.warning("%s | Attempt %d failed", error, number_of_retries_made + 1)
                if number_of_retries_made != max_retries - 1:  # No delay if final attempt fails
                    await backoff_delay_async(1, number_of_retries_made)
        logger.error("URL: %s GET request failed! Errors: %s", url, errors)
        return (url, b"{}")  # Allow json.loads to parse body if request fails

    # GET request timeout of 5 minutes (300 seconds)
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=0, ttl_dns_cache=300),
        raise_for_status=True,
        timeout=aiohttp.ClientTimeout(total=300),
    ) as session:
        # Only one instance of any duplicate endpoint will be used
        return await gather_with_concurrency(
            max_concurrent_requests, *[get(url, session) for url in set(endpoints)]
        )


def current_datetime_str() -> str:
    """Current time's datetime string in UTC.

    Returns:
        str: Timestamp in strftime format "%d_%b_%Y_%H_%M_%S-UTC"
    """
    return datetime.datetime.now(datetime.UTC).strftime("%d_%b_%Y_%H_%M_%S-UTC")


async def extract_ips() -> set[str]:
    """Extract IPs from https://threatfox.abuse.ch/export/csv/ip-port/full

    Returns:
        set[str]: Unique IPs
    """
    endpoint: str = "https://threatfox.abuse.ch/export/csv/ip-port/full"
    ips: set[str] = set()
    try:
        response = (await get_async([endpoint]))[endpoint]
        with zipfile.ZipFile(io.BytesIO(response)) as z:
            with z.open(z.infolist()[0]) as file:
                reader = csv.reader(io.TextIOWrapper(file, 'utf-8'))
                for row in reader:
                    if len(row) >= 3:
                        ip_port = row[2].strip().replace('"', "")
                        ip, _, _ = ip_port.partition(":")
                        try:
                            socket.inet_pton(socket.AF_INET, ip)
                            ips.add(ip)
                        except socket.error:
                            pass
        logger.info("%s extracted!", z.infolist()[0].filename)
    except Exception as error:
        logger.error(error)
    return ips


if __name__ == "__main__":
    ips: set[str] = asyncio.run(extract_ips())
    if ips:
        timestamp: str = current_datetime_str()
        filename = "ips.txt"
        ip_addresses = list(ips)
        ip_addresses.sort(key=ipaddress.IPv4Address)
        with open(filename, "w") as f:
            f.writelines("\n".join(ip_addresses))
            logger.info("%d IPs written to %s at %s", len(ips), filename, timestamp)
    else:
        raise ValueError("No IP addresses found!")
