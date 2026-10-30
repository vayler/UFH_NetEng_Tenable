"""Build an authenticated TenableIO client from environment variables / .env."""

import os

from dotenv import load_dotenv

from tenable_net import __version__


class MissingCredentials(RuntimeError):
    pass


def get_client():
    """Return a TenableIO client using TIO_ACCESS_KEY / TIO_SECRET_KEY."""
    # Imported lazily so report/summary commands work from cache without pyTenable installed.
    from tenable.io import TenableIO

    load_dotenv()
    access_key = os.getenv("TIO_ACCESS_KEY")
    secret_key = os.getenv("TIO_SECRET_KEY")
    if not access_key or not secret_key:
        raise MissingCredentials(
            "TIO_ACCESS_KEY and TIO_SECRET_KEY must be set (in the environment or a .env file). "
            "See .env.example."
        )

    kwargs = {}
    if os.getenv("TIO_URL"):
        kwargs["url"] = os.getenv("TIO_URL")

    # vendor/product/build identify this integration in Tenable's User-Agent, per their guidance.
    return TenableIO(
        access_key=access_key,
        secret_key=secret_key,
        vendor="UFH NetEng",
        product="tenable_net",
        build=__version__,
        **kwargs,
    )
