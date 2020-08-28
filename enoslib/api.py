# -*- coding: utf-8 -*-
from collections import namedtuple
import copy
import logging
import os
import tempfile
from typing import Any, List, MutableMapping, Mapping, Optional, Union, Set
import time
import json
import yaml


# These two imports are 2.9
from ansible.module_utils.common.collections import ImmutableDict
from ansible import context
from ansible.executor import task_queue_manager
from ansible.executor.playbook_executor import PlaybookExecutor

# Note(msimonin): PRE 2.4 is
# from ansible.inventory import Inventory
from ansible.parsing.dataloader import DataLoader
from ansible.playbook import play
from ansible.plugins.callback.default import CallbackModule

# Note(msimonin): PRE 2.4 is
# from ansible.vars import VariableManager
from ansible.vars.manager import VariableManager

from enoslib.enos_inventory import EnosInventory
from enoslib.utils import _check_tmpdir, get_roles_as_list
from enoslib.errors import (
    EnosFailedHostsError,
    EnosUnreachableHostsError,
    EnosSSHNotReady,
)
from enoslib.types import Roles, Networks, Host

logger = logging.getLogger(__name__)




def get_hosts(roles: Roles, pattern_hosts: str = "all") -> List[Host]:
    """Get all the hosts matching the pattern.

    Args:
        roles: the roles as returned by
            :py:meth:`enoslib.infra.provider.Provider.init`
        pattern_hosts: pattern to describe ansible hosts to target.
            see https://docs.ansible.com/ansible/latest/intro_patterns.html

    Return:
        The list of hosts matching the pattern
    """
    all_hosts: Set[Host] = set()
    for hosts in roles.values():
        all_hosts = all_hosts.union(set(hosts))
    inventory = EnosInventory(roles=roles)
    ansible_hosts = inventory.get_hosts(pattern=pattern_hosts)
    ansible_addresses = [h.address for h in ansible_hosts]
    return [h for h in all_hosts if h.address in ansible_addresses]


# Private zone
