"""Build an authenticated TenableIO client from environment variables / .env."""

import os

from dotenv import find_dotenv, load_dotenv, set_key

from tenable_net import __version__


class MissingCredentials(RuntimeError):
    pass


def env_path():
    """The .env file in use: the nearest one above the working directory, else ./.env."""
    return find_dotenv(usecwd=True) or os.path.join(os.getcwd(), ".env")


def get_client(access_key=None, secret_key=None):
    """Return a TenableIO client using the given keys, or TIO_ACCESS_KEY / TIO_SECRET_KEY."""
    # Imported lazily so report/summary commands work from cache without pyTenable installed.
    from tenable.io import TenableIO

    load_dotenv(env_path())
    access_key = access_key or os.getenv("TIO_ACCESS_KEY")
    secret_key = secret_key or os.getenv("TIO_SECRET_KEY")
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


def saved_credentials():
    """Return (access_key, secret_key) from the environment / .env, either may be None."""
    load_dotenv(env_path())
    return os.getenv("TIO_ACCESS_KEY"), os.getenv("TIO_SECRET_KEY")


def save_credentials(access_key, secret_key, path=None):
    """Write the keys to .env and the current process environment."""
    path = path or env_path()
    open(path, "a").close()  # set_key needs the file to exist
    for key, value in (("TIO_ACCESS_KEY", access_key), ("TIO_SECRET_KEY", secret_key)):
        set_key(path, key, value, quote_mode="never")
        os.environ[key] = value
