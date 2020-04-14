# -*- coding: utf-8 -*-
from datetime import datetime
from functools import wraps
import logging
from typing import Dict, Optional, Union
from pathlib import Path
import pickle
import yaml

from enoslib.constants import SYMLINK_NAME, ENV_FILENAME
from enoslib.errors import EnosFilePathError

# Following this bug
# https://intranet.grid5000.fr/bugzilla/show_bug.cgi?id=10266
# we force the task to know about host
from enoslib.host import Host  # noqa


logger = logging.getLogger(__name__)


def _symlink_to(env_dir: Path):
    try:
        if SYMLINK_NAME.exists():
            # in 3.8 we'd like to use missing_ok
            SYMLINK_NAME.unlink()
        SYMLINK_NAME.symlink_to(env_dir.resolve())
        logger.info(f"Symlink {env_dir} to {SYMLINK_NAME}")
    except OSError:
        # An harmless error can occur due to a race condition when
        # multiple regions are simultaneously deployed
        logger.info(f"Symlink {env_dir} to {SYMLINK_NAME} failed")


def _create_env_dir(env_dir: Path):
    """Create the env_dir

    Looks at the `env_dir` and create the directory if it doesn't exist.
    Links the directory to `SYMLINK_NAME`.

    Args:
        env_dir: file path to a directory.
    """
    # Raise error if a related file exists
    if env_dir.is_file():
        raise EnosFilePathError(env_dir, f"Already existing {env_dir}, not overwriting")

    # Create the result directory if it does not exist
    if not env_dir.is_dir():
        env_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Generate environment directory {env_dir}")


class Environment:
    def __init__(self, env_name: Path):
        env_name.mkdir(parents=True, exist_ok=True)
        self.env_name = env_name.resolve()
        self.__store: Dict = {
            # this resultdir was used to store the env_name
            # in the previous version
            # we keep it for backward compatibility purpose
            "resultdir": self.env_name,
            # store the path to a configuration file if any
            "config_file": None,
            # the configuration itself
            "config": {},
            # unused for now, let's see if we can handle different
            # configuration format
            "config_type": "yaml"}

    def get(self, key, default=None):
        return self.__store.get(key, default)

    def __getitem__(self, key):
        return self.__store[key]

    def __setitem__(self, key, value):
        self.__store[key] = value

    @classmethod
    def load_from_file(cls, env_file: Path):
        if not env_file.is_file():
            raise EnosFilePathError(
                env_file, f"{env_file} doesn't exist, not reloading"
            )

        with env_file.open(mode="rb") as f:
            self = pickle.load(f)
            # fix path to the environment
            self.env_name = env_file.parent.resolve()
            logger.debug(f"Loaded environment {env_file}")
        return self

    def dumps(self):
        return pickle.dumps(self)

    def dump(self):
        self.env_name.mkdir(parents=True, exist_ok=True)
        env_file = self.env_name.joinpath(ENV_FILENAME)
        with env_file.open("wb") as f:
            f.write(self.dumps())

    def reload_config(self):
        """reload a config file if any in the store."""
        if self.get("config_file"):
            # Resets the configuration of the environment
            config_path = Path(self["config_file"])
            if config_path.is_file():
                with config_path.open(mode="r") as f:
                    self["config"].update(yaml.load(f))
                    logger.debug("Reloaded config %s", self["config"])


def get_or_create_env(
    new: bool, env_name: Optional[Union[Environment, Path, str]], symlink=True
):
    if isinstance(env_name, Environment):
        env = env_name
    elif isinstance(env_name, str):
        env_file = Path(env_name).joinpath(ENV_FILENAME)
        env = Environment.load_from_file(env_file)
    elif isinstance(env_name, Path):
        env_file = env_name.joinpath(ENV_FILENAME)
        env = Environment.load_from_file(env_file)
    elif env_name is None:
        if new:
            # regardless the existing env, we create a new one
            env_dir = Path("enos_" + datetime.today().isoformat())
            env_file = env_dir.joinpath(ENV_FILENAME)
            # This prepares the env_dir
            _create_env_dir(env_dir)
            # Create a new env
            env = Environment(env_dir)
            if symlink:
                _symlink_to(env.env_name)
        else:
            # otherwise we try to reuse an existing one
            env = Environment.load_from_file(SYMLINK_NAME.joinpath(ENV_FILENAME))
    else:
        raise EnosFilePathError(
            env_name, "You must pass an Environment or a Path or string path"
        )

    return env


def enostask(new: bool = False, symlink: bool = True):
    """Decorator for an Enos Task.

    This decorator lets you define a new Enos task and helps you manage the
    environment. It injects the environment in the function called.

    Args:
        new (bool): indicates if a new environment must be created.
            Usually this is set on the first task of the workflow.
        symlink (bool): indicates if the env in use must be symlinked
            (ignored if new=False)

    Examples:

        .. code-block:: python

            @enostask(new=True)
            def foo(env=None, **kwargs):
                # The key resultdir is available once the env is created
                print(env["resultdir"])

            @enostask()
            def myfunction(env=None, **kwargs):
                # saving a new key
                env['foo'] = 'bar'
    """

    def decorator(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            # Constructs the environment
            # --env or env are reserved keyword to reuse existing env
            env_name = kwargs.get("--env") or kwargs.get("env")
            symlink = kwargs.get("env_symlink", True)
            env = get_or_create_env(new, env_name, symlink=symlink)
            env.reload_config()
            kwargs["env"] = env
            try:
                # Proceeds with the function execution
                logger.info("- Task %s started -" % fn.__name__)
                r = fn(*args, **kwargs)
                logger.info("- Task %s finished -" % fn.__name__)
                return r
            finally:
                # Save the environment
                env.dump()

        return decorated

    return decorator
