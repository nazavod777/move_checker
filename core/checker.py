import asyncio

import aiohttp
from eth_account import Account
from loguru import logger
from tenacity import retry
from web3.auto import w3

from utils import append_file
from utils import get_proxy
from utils import loader

Account.enable_unaudited_hdwallet_features()


def log_retry_error(retry_state):
    logger.error(retry_state.outcome.exception())


class Checker:
    def __init__(self,
                 client: aiohttp.ClientSession,
                 account_data: str,
                 account_address: str):
        self.client: aiohttp.ClientSession = client
        self.account_data: str = account_data
        self.account_address: str = account_address

    @retry(after=log_retry_error)
    async def _check_eligible(self) -> int:
        response_text: None = None

        try:
            r: aiohttp.ClientResponse = await self.client.post(
                url=f'https://claim.tokentable.xyz/api/airdrop-open/query',
                proxy=get_proxy(),
                json={
                    'projectId': 'AD_2aC4CiCsqKR1',
                    'recipient': self.account_address,
                    'recipientType': 'WalletAddress',
                }
            )
            response_text: str = await r.text()
            response_json: dict = await r.json(content_type=None)

            return sum([int(current_data['amount']) for current_data in response_json['data']['claims']]) / 10 ** 8

        except Exception as error:
            raise Exception(
                f'{self.account_address} | Unexpected Error When Checking Eligible: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    async def check_account(self) -> None:
        tokens_amount: float = await self._check_eligible()

        if tokens_amount <= 0:
            logger.error(f'{self.account_address} | Not Eligible')
            return

        async with asyncio.Lock():
            await append_file(
                file_path='result/eligible.txt',
                file_content=f'{self.account_data} | {self.account_data} | {tokens_amount} $MOVE\n'
            )

        logger.success(f'{self.account_data} | {self.account_address} | {tokens_amount} $MOVE')


async def check_account(
        client: aiohttp.ClientSession,
        account_data: str
) -> None:
    async with loader.semaphore:
        account_address: None = None

        try:
            account_address: str = Account.from_key(private_key=account_data).address

        except Exception:
            pass

        if not account_address:
            try:
                account_address: str = Account.from_mnemonic(mnemonic=account_data).address

            except Exception:
                pass

        if not account_address:
            try:
                account_address: str = w3.to_checksum_address(value=account_data)

            except Exception:
                pass

        if not account_address:
            logger.error(f'{account_data} | Not Mnemonic and not PKey')
            return

        checker: Checker = Checker(
            client=client,
            account_data=account_data,
            account_address=account_address
        )
        await checker.check_account()
