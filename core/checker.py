import asyncio

import aiohttp
from eth_account import Account
from eth_account.account import LocalAccount
from eth_account.messages import encode_defunct
from loguru import logger
from tenacity import retry

from utils import append_file
from utils import get_proxy
from utils import loader

Account.enable_unaudited_hdwallet_features()


def log_retry_error(retry_state):
    logger.error(retry_state.outcome.exception())


class Checker:
    def __init__(self,
                 client: aiohttp.ClientSession,
                 account: LocalAccount):
        self.client: aiohttp.ClientSession = client
        self.account: LocalAccount = account

    @retry(after=log_retry_error)
    async def _get_nonce(self) -> str:
        response_text: None = None

        try:
            r: aiohttp.ClientResponse = await self.client.get(
                url='https://claims.movementnetwork.xyz/api/get-nonce',
                proxy=get_proxy()
            )

            response_text: str = await r.text()
            response_json: dict = await r.json(content_type=None)

            return response_json['nonce']

        except Exception as error:
            raise Exception(
                f'{self.account.address} | Error When Getting Nonce: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    @retry(after=log_retry_error)
    async def _check_eligible(self,
                             nonce: str) -> tuple[float | None, float | None, bool | None, bool | None, bool | None]:
        response_text: None = None

        try:
            signed_message_hash: str = self.account.sign_message(
                signable_message=encode_defunct(
                    text=f'Please sign this message to confirm ownership. nonce: {nonce}')).signature.hex()

            r: aiohttp.ClientResponse = await self.client.post(
                url=f'https://claims.movementnetwork.xyz/api/claim/start',
                proxy=get_proxy(),
                json={
                    'address': self.account.address,
                    'message': f'Please sign this message to confirm ownership. nonce: {nonce}',
                    'nonce': nonce,
                    'signature': signed_message_hash if signed_message_hash.startswith(
                        '0x') else f'0x{signed_message_hash}'
                }
            )
            response_text: str = await r.text()
            response_json: dict = await r.json(content_type=None)

            if response_json.get('eligibility_status', '') == 'not_eligible':
                return None, None, None, None, None

            if not response_json.get('amount', None):
                raise Exception(f'{self.account.address} | Wrong Response When Checking Eligible: {response_text}')

            return int(response_json['amount']), int(response_json['amountL2']), response_json['isOKXUser'], response_json['claimedOnL1'], response_json['claimedOnL2']

        except Exception as error:
            raise Exception(
                f'{self.account.address} | Unexpected Error When Checking Eligible: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    async def check_account(self) -> None:
        nonce: str = await self._get_nonce()
        allocation_l1, allocation_l2, is_okx_user, is_claimed_on_l1, is_claimed_on_l2 = await self._check_eligible(nonce=nonce)

        if not allocation_l1 or allocation_l1 <= 0:
            logger.error(f'{self.account.address} | Not Eligible')
            return

        async with asyncio.Lock():
            await append_file(
                file_path='result/eligible.txt',
                file_content=f'{self.account.key.hex()} | {allocation_l1} $MOVE L1 | {allocation_l2} | {allocation_l2} $MOVE L2 | OKX USER: {is_okx_user} | CLAIMED ON L1: {is_claimed_on_l1} | CLAIMED ON L2: {is_claimed_on_l2}\n'
            )

        logger.success(f'{self.account.address} | {self.account.key.hex()} | {allocation_l1} $MOVE L1 | {allocation_l2} | {allocation_l2} $MOVE L2 | OKX USER: {is_okx_user} | CLAIMED ON L1: {is_claimed_on_l1} | CLAIMED ON L2: {is_claimed_on_l2}')


async def check_account(
        client: aiohttp.ClientSession,
        account_data: str
) -> None:
    async with loader.semaphore:
        account: None = None

        try:
            account: LocalAccount = Account.from_key(private_key=account_data)

        except Exception:
            pass

        if not account:
            try:
                account: LocalAccount = Account.from_mnemonic(mnemonic=account_data)

            except Exception:
                pass

        if not account:
            logger.error(f'{account_data} | Not Mnemonic and not PKey')
            return

        checker: Checker = Checker(
            client=client,
            account=account
        )
        await checker.check_account()
