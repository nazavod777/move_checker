import asyncio
from os import mkdir
from os.path import exists
from sys import stderr

import aiohttp
from loguru import logger

from core import check_account
from utils import loader

logger.remove()
logger.add(stderr, format='<white>{time:HH:mm:ss}</white>'
                          ' | <level>{level: <8}</level>'
                          ' | <cyan>{line}</cyan>'
                          ' - <white>{message}</white>')


async def main() -> None:
    loader.semaphore = asyncio.Semaphore(value=threads)

    async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                verify_ssl=None,
                ssl=False,
                use_dns_cache=False,
                ttl_dns_cache=300,
                limit=None
            ),
            headers={
                'accept': '*/*',
                'accept-language': 'ru,en;q=0.9,vi;q=0.8,es;q=0.7,cy;q=0.6',
                'content-type': 'application/json',
                'origin': 'https://claims.movementnetwork.xyz',
                'referer': 'https://claims.movementnetwork.xyz'
            }
    ) as client:
        tasks: list[asyncio.Task] = [
            asyncio.create_task(
                coro=check_account(
                    client=client,
                    account_data=current_account_data
                )
            )
            for current_account_data in accounts_list
        ]

        await asyncio.gather(*tasks)


if __name__ == '__main__':
    if not exists(
            'result'
    ):
        mkdir(
            'result'
        )
    with open(
            file='data/accounts.txt',
            mode='r',
            encoding='utf-8-sig'
    ) as file:
        accounts_list: list[str] = [row.strip().split(':')[0] for row in file if row]

    logger.success(f'Successfully Loaded {len(accounts_list)} Accounts')
    threads: int = int(input('\nThreads: '))
    print()

    asyncio.run(main())

    logger.success('The Work Has Been Successfully Finished')
    input('\nPress Enter to Exit..')
