from collections import namedtuple
import copy
import json
import logging
import tempfile
import time
from typing import Any, List, Optional, MutableMapping, Mapping, Union
from pathlib import Path
import os
import yaml

# These two imports are 2.9
from ansible.module_utils.common.collections import ImmutableDict
from ansible import context
from ansible.executor import task_queue_manager
from ansible.executor.playbook_executor import PlaybookExecutor
from ansible.inventory.manager import InventoryManager

# Note(msimonin): PRE 2.4 is
# from ansible.inventory import Inventory
from ansible.parsing.dataloader import DataLoader
from ansible.playbook import play
from ansible.plugins.callback.default import CallbackModule

# Note(msimonin): PRE 2.4 is
# from ansible.vars import VariableManager
from ansible.vars.manager import VariableManager

# misc
from netaddr import IPAddress, IPSet

from . import Launcher
from enoslib.constants import ANSIBLE_DIR, TMP_DIRNAME
from enoslib.objects import Inventory, HostInventory, NetworkInventory
from enoslib.errors import (
    EnosSSHNotReady,
    EnosUnreachableHostsError,
    EnosFailedHostsError,
)
from enoslib.utils import _check_tmpdir, get_roles_as_list

logger = logging.getLogger(__name__)


COMMAND_NAME = "enoslib_adhoc_command"
STATUS_OK = "OK"
STATUS_FAILED = "FAILED"
STATUS_UNREACHABLE = "UNREACHABLE"
STATUS_SKIPPED = "SKIPPED"
DEFAULT_ERROR_STATUSES = {STATUS_FAILED, STATUS_UNREACHABLE}
# The following translate the keywords passed in the play_on tasks to
# actual ansible keywords. We do that because async became a reserved keyword
# in python3.7 so on can't write :
# with play_on() as p
#   p.shell(..., async=100)
# But rather will need to write (with an h!)
# with play_on() as p
#   p.shell(..., asynch=100)
ANSIBLE_TOP_LEVEL = {
    "asynch": "async",
    "become": "become",
    "become_user": "become_user",
    "become_method": "become_method",
    "loop": "loop",
    "poll": "poll",
    "ignore_errors": "ignore_errors",
    "environment": "environment",
    "when": "when",
}


def _split_args(**kwargs):
    """Splits top level kwargs and module specific kwargs."""
    top_args = {}
    module_args = {}
    for k, v in kwargs.items():
        if k in ANSIBLE_TOP_LEVEL.keys():
            top_args.update({ANSIBLE_TOP_LEVEL[k]: v})
        else:
            module_args.update({k: v})
    return top_args, module_args


def _load_defaults(
    hosts: Union[HostInventory, Path], extra_vars=None, tags=None, basedir=False
):
    """Load common defaults data structures.

    For factorization purpose."""

    extra_vars = extra_vars or {}
    tags = tags or []
    loader = DataLoader()
    if basedir:
        loader.set_basedir(basedir)

    # new api: this is where we can differentiate the inventory file/inmem role
    ansible_inventory = EnosInventory(loader=loader, hosts=hosts)

    variable_manager = VariableManager(loader=loader, inventory=ansible_inventory)

    # seems mandatory to load group_vars variable
    if basedir:
        variable_manager.safe_basedir = True

    if extra_vars:
        # 2.9: we hack this, normally extra_vars are loaded from the
        # context.CLIARGS.extra_vars that can be loaded from the cli, or a file,..
        # self._extra_vars = load_extra_vars(loader=self._loader)
        # in variable manager constructor
        variable_manager._extra_vars = extra_vars

    # NOTE(msimonin): The ansible api is "low level" in the
    # sense that we are redefining here all the default values
    # that are usually enforce by ansible called from the cli
    context.CLIARGS = ImmutableDict(
        start_at_task=None,
        listtags=False,
        listtasks=False,
        listhosts=False,
        syntax=False,
        connection="ssh",
        module_path=None,
        forks=100,
        private_key_file=None,
        ssh_common_args=None,
        ssh_extra_args=None,
        sftp_extra_args=None,
        scp_extra_args=None,
        become=False,
        become_method="sudo",
        become_user="root",
        remote_user=None,
        verbosity=2,
        check=False,
        tags=tags,
        diff=None,
        basedir=basedir,
    )

    return ansible_inventory, variable_manager, loader


_AnsibleExecutionRecord = namedtuple(
    "AnsibleExecutionRecord", ["host", "status", "task", "payload"]
)


class EnosInventory(InventoryManager):
    def __init__(self, hosts: Union[HostInventory, Path], loader=None):

        # TODO(msimonin): check type

        if loader is None:
            loader = DataLoader()

        sources = None
        if isinstance(hosts, Path):
            sources = str(hosts)
        # init anyway an ansible inventory with all the associated attributes
        super(EnosInventory, self).__init__(loader, sources=sources)
        if isinstance(hosts, HostInventory):
            self._populate_with_roles(hosts)

    def _populate_with_roles(self, hosts: HostInventory):
        for role, machines in hosts.iter_roles():
            self.add_group(role)
            for machine in machines:
                self.add_host(machine.alias, group=role)
                # let's add some variabe to that host
                host = self.get_host(machine.alias)
                host.address = machine.address
                if machine.user is not None:
                    host.set_variable("ansible_ssh_user", machine.user)
                if machine.port is not None:
                    host.set_variable("ansible_port", machine.port)
                if machine.keyfile is not None:
                    host.set_variable("ansible_ssh_private_key_file", machine.keyfile)
                common_args = []
                common_args.append("-o StrictHostKeyChecking=no")
                common_args.append("-o UserKnownHostsFile=/dev/null")
                forward_agent = machine.extra.get("forward_agent", False)
                if forward_agent:
                    common_args.append("-o ForwardAgent=yes")

                gateway = machine.extra.get("gateway", None)
                if gateway is not None:
                    proxy_cmd = ["ssh -W %h:%p"]
                    # Disabling also hostkey checking for the gateway
                    proxy_cmd.append("-o StrictHostKeyChecking=no")
                    proxy_cmd.append("-o UserKnownHostsFile=/dev/null")
                    gateway_user = machine.extra.get("gateway_user", machine.user)
                    if gateway_user is not None:
                        proxy_cmd.append("-l %s" % gateway_user)

                    proxy_cmd.append(gateway)
                    proxy_cmd = " ".join(proxy_cmd)
                    common_args.append('-o ProxyCommand="%s"' % proxy_cmd)

                common_args = " ".join(common_args)
                host.set_variable("ansible_ssh_common_args", "{}".format(common_args))

                for k, v in machine.extra.items():
                    if k not in ["gateway", "gateway_user", "forward_agent"]:
                        host.set_variable(k, v)

        self.reconcile_inventory()

    def to_ini_string(self):
        def to_inventory_string(v):
            """Handle the cas of List[String]."""
            if isinstance(v, list):
                # [a, b, c] -> "['a','b','c']"
                s = map(lambda x: "'%s'" % x, v)
                s = '"[%s]"' % ",".join(s)
                return s
            return "'{}'".format(v)

        s = []
        for role, hostnames in self.get_groups_dict().items():
            s.append("[{}]".format(role))
            for hostname in hostnames:
                h = self.get_host(hostname)
                i = ["ansible_host={}".format(h.address)]
                # NOTE(mimonin): The intend of generating an ini is because we
                # want an inventory_file and and inventory dir set so removing
                # those keys (None values).
                for k, v in h.vars.items():
                    if k in ["inventory_file", "inventory_dir"]:
                        continue
                    i.append("{}={}".format(k, to_inventory_string(v)))
                # For determinism purpose (e.g unit tests)
                i = sorted(i)
                # Adding the inventory_hostname in front of the line
                i = [h.name] + i
                s.append(" ".join(i))
        return "\n".join(s)


class AnsibleLauncher(Launcher):
    """Runs stuffs on machines using Ansible..."""

    def __init__(self, inventory: Union[Inventory, Path]):
        self.hosts = inventory.hosts_inventory()
        self.networks = inventory.networks_inventory()

    def discover_networks(
        self, fake_interfaces: List[str] = None, fake_networks: List[str] = None
    ) -> Inventory:
        """Checks the network interfaces on the nodes.

        This enables to auto-discover the mapping interface name <-> network role.

        Args:
            roles (dict): role->hosts mapping as returned by
                :py:meth:`enoslib.infra.provider.Provider.init`
            networks (list): network list as returned by
                :py:meth:`enoslib.infra.provider.Provider.init`
            fake_interfaces (list): names of optionnal dummy interfaces to create
            fake_networks (list): names of the roles to associate with the fake
                interfaces. Like regular network interfaces, the mapping will be
                added to the host vars. Internally this will be zipped with the
                fake_interfaces to produce the mapping.

        If the command is successful each host will be added some variables.
        Assuming that one network whose role is `mynetwork` has been declared, the
        following variables will be available through the ansible hostvars:

        - ``mynetwork=eth1``, `eth1` has been discovered has the interface in the
        network `mynetwork`.
        - ``mynetwork_dev=eth1``, same as above with a different accessor names
        - ``mynetwork_ip=192.168.42.42``, this indicates the ip in the network
        `mynetwork` for this node

        All of this variable can then be accessed by the other nodes through the
        hostvars: ``hostvars[remote_node]["mynetwork_ip"]``
        """

        def get_devices(facts):
            """Extract the network devices information from the facts."""
            devices = []
            for interface in facts["ansible_interfaces"]:
                ansible_interface = "ansible_" + interface
                # filter here (active/ name...)
                if "ansible_" + interface in facts:
                    interface = facts[ansible_interface]
                    devices.append(interface)
            return devices

        self.wait_ssh()
        tmpdir = os.path.join(os.getcwd(), TMP_DIRNAME)
        _check_tmpdir(tmpdir)
        fake_interfaces = fake_interfaces or []
        fake_networks = fake_networks or []

        utils_playbook = os.path.join(ANSIBLE_DIR, "utils.yml")
        facts_file = os.path.join(tmpdir, "facts.json")
        options = {
            "enos_action": "check_network",
            "facts_file": facts_file,
            "fake_interfaces": fake_interfaces,
        }
        self.ansible_run([utils_playbook], extra_vars=options, on_error_continue=False)

        # Read the file
        # Match provider networks to interface names for each host
        with open(facts_file) as f:
            facts = json.load(f)
            for _, host_facts in facts.items():
                host_nets = _map_device_on_host_networks(
                    self.networks, get_devices(host_facts)
                )
                # Add the mapping : networks <-> nic name
                host_facts["networks"] = host_nets

        # Finally update the env with this information
        # generate the extra_mapping for the fake interfaces
        extra_mapping = dict(zip(fake_networks, fake_interfaces))

        new_hosts = _update_hosts(self.hosts, facts, extra_mapping=extra_mapping)
        return Inventory(new_hosts, self.networks)

    def gather_facts(
        self,
        *,
        pattern_hosts="all",
        gather_subset="all",
        extra_vars=None,
        on_error_continue=False,
    ):
        """Gather facts about hosts.


        This function can be used to check/save the information of the
        infrastructure where the experiment ran. It'll give the information
        gathered by Ansible (see
        https://docs.ansible.com/ansible/latest/user_guide/playbooks_variables.html
        )

        Args:
            pattern_hosts (str): pattern to describe ansible hosts to target.
                see https://docs.ansible.com/ansible/latest/intro_patterns.html
            gather_subset (str): if supplied, restrict the additional facts
                collected to the given subset.
                https://docs.ansible.com/ansible/latest/modules/setup_module.html
            inventory_path (str): inventory to use
            roles (dict): the roles to use (replacement for inventory_path).
            extra_vars (dict): extra_vars to use
            on_error_continue(bool): Don't throw any exception in case a host is
                unreachable or the playbooks run with errors

        Raises:
            :py:class:`enoslib.errors.EnosFailedHostsError`: if a task returns an
                error on a host and ``on_error_continue==False``
            :py:class:`enoslib.errors.EnosUnreachableHostsError`: if a host is
                unreachable (through ssh) and ``on_error_continue==False``

        Returns:
            Dict combining the ansible facts of ok and failed hosts and every
            results of tasks executed.

        Example:

        .. code-block:: python

            # Inventory
            [control1]
            enos-0
            [control2]
            enos-1

            # Python
            result = gather_facts(roles=roles)

            # Result
            {
                'failed': {},
                'ok':
                {
                'enos-0':
                {
                    'ansible_product_serial': 'NA',
                    'ansible_form_factor': 'Other',
                    'ansible_user_gecos': 'root',
                    ...
                },
                'enos-1':
                {...}
                'results': [...]
            }

        """

        def filter_results(results, status):
            _r = [r for r in results if r.status == status and r.task == COMMAND_NAME]
            s = dict([[r.host, r.payload.get("ansible_facts")] for r in _r])
            return s

        play_source = {
            "hosts": pattern_hosts,
            "tasks": [
                {"name": COMMAND_NAME, "setup": {"gather_subset": gather_subset}}
            ],
        }
        results = self.ansible_play(
            self.hosts,
            play_source,
            extra_vars=extra_vars,
            on_error_continue=on_error_continue,
        )
        ok = filter_results(results, STATUS_OK)
        failed = filter_results(results, STATUS_FAILED)

        return {"ok": ok, "failed": failed, "results": results}

    def ansible_inventory(
        self,
        inventory_path: str,
        *,
        check_networks=False,
        fake_interfaces=None,
        fake_networks=None,
    ):
        """Generate an inventory file in the ini format.

        The inventory is generated using the ``roles`` in the ``ini`` format.  If
        ``check_network == True``, the function will try to discover which networks
        interfaces are available and map them to one network of the ``networks``
        parameters.  Note that this auto-discovery feature requires the servers to
        have their IP set.

        Args:
            roles (dict): role->hosts mapping as returned by
                :py:meth:`enoslib.infra.provider.Provider.init`
            networks (list): network list as returned by
                :py:meth:`enoslib.infra.provider.Provider.init`
            inventory_path (str): path to the inventory to generate
            check_networks (bool): True to enable the auto-discovery of the mapping
                interface name <-> network role
            fake_interfaces (list): names of optionnal dummy interfaces to create
                on the nodes
            fake_networks (list): names of the roles to associate with the fake
                interfaces. Like reguilar network interfaces, the mapping will be
                added to the host vars. Internally this will be zipped with the
                fake_interfaces to produce the mapping. """

        def _generate_inventory(hosts):
            """Generates an inventory files from roles

            :param roles: dict of roles (roles -> list of Host)
            """
            inventory = EnosInventory(hosts)
            return inventory.to_ini_string()

        with open(inventory_path, "w") as f:
            f.write(_generate_inventory(self.hosts))

        if check_networks:
            new_inventory = self.discover_networks(
                fake_interfaces=fake_interfaces, fake_networks=fake_networks
            )
            with open(inventory_path, "w") as f:
                f.write(_generate_inventory(new_inventory.hosts))

    def run_cmd(
        self,
        cmd: str,
        *,
        pattern_hosts: str = "all",
        extra_vars: Optional[Mapping] = None,
        on_error_continue: bool = False,
        run_as: Optional[str] = None,
        **kwargs: Any,
    ):
        """Run a shell command on some remote hosts.

        Args:
            cmd (str): the command to run
            pattern_hosts (str): pattern to describe ansible hosts to target.
                see https://docs.ansible.com/ansible/latest/intro_patterns.html
            inventory_path (str): inventory to use
            roles (dict): the roles to use (replacement for inventory_path).
            extra_vars (dict): extra_vars to use
            on_error_continue(bool): Don't throw any exception in case a host is
                unreachable or the playbooks run with errors
            run_as(str): run the command as this user.
                This is equivalent to passing become=yes and become_user=user but
                become_method can be passed to modify the priviledge escalation
                method. (default to sudo).
            kwargs: keywords argument to pass to the shell module or as top level
                args.

        Raises:
            :py:class:`enoslib.errors.EnosFailedHostsError`: if a task returns an
                error on a host and ``on_error_continue==False``
            :py:class:`enoslib.errors.EnosUnreachableHostsError`: if a host is
                unreachable (through ssh) and ``on_error_continue==False``

        Returns:
            Dict combining the stdout and stderr of ok and failed hosts and every
            results of tasks executed (this may include the fact gathering tasks)

        Example:

        .. code-block:: python

            # Inventory
            [control1]
            enos-0
            [control2]
            enos-1

            # Python
            result = run_cmd("date", inventory)

            # Result
            {
                'failed': {},
                'ok':
                {
                    u'enos-0':
                    {
                        'stderr': u'',
                        'stdout': u'Tue Oct 31 04:53:04 GMT 2017'
                    },
                    u'enos-1':
                    {
                        'stderr': u'',
                        'stdout': u'Tue Oct 31 04:53:05 GMT 2017'}
                    },
                'results': [...]
            }

        If facts are gathered it is possible to use ansible templating

        .. code-block:: python

            result = run_cmd("control*", "ping -c 1
            {{hostvars['enos-1']['ansible_' + n1].ipv4.address}}", inventory)


        Command can be run asynchronously using the corresponding Ansible options
        (see https://docs.ansible.com/ansible/latest/user_guide/playbooks_async.html)

        .. code-block:: python

            result = run_cmd("date", roles=roles, async=20, poll=0)

        Note that the actual result isn't available in the result file but will be
        available through a file specified in the result object. """

        def filter_results(results, status):
            _r = [r for r in results if r.status == status and r.task == COMMAND_NAME]
            s = dict(
                [
                    [
                        r.host,
                        {
                            "stdout": r.payload.get("stdout"),
                            "stderr": r.payload.get("stderr"),
                        },
                    ]
                    for r in _r
                ]
            )
            return s

        if run_as is not None:
            # run_as is a shortcut
            kwargs.update(become=True, become_user=run_as)

        task = {"name": COMMAND_NAME, "shell": cmd}

        top_args, module_args = _split_args(**kwargs)
        task.update(top_args)
        task.update(args=module_args)

        play_source = {"hosts": pattern_hosts, "tasks": [task]}

        results = self.ansible_play(play_source, extra_vars=extra_vars)
        ok = filter_results(results, STATUS_OK)
        failed = filter_results(results, STATUS_FAILED)
        # TODO(msimonin): encapsulate this

        return {"ok": ok, "failed": failed, "results": results}

    def ansible_play(self, play_source, *, extra_vars=None, on_error_continue=False):
        """Run a play.

        Args:
            play_source (dict): ansible task
            inventory_path (str): inventory to use
            extra_vars (dict): extra_vars to use
            on_error_continue(bool): Don't throw any exception in case a host is
                unreachable or the playbooks run with errors

        Raises:
            :py:class:`enoslib.errors.EnosFailedHostsError`: if a task returns an
                error on a host and ``on_error_continue==False``
            :py:class:`enoslib.errors.EnosUnreachableHostsError`: if a host is
                unreachable (through ssh) and ``on_error_continue==False``

        Returns:
            List of all the results
        """
        logger.debug(play_source)
        print(extra_vars)
        results = []
        inventory, variable_manager, loader = _load_defaults(
            self.hosts, extra_vars=extra_vars
        )
        callback = _MyCallback(results)
        passwords = {}
        tqm = task_queue_manager.TaskQueueManager(
            inventory=inventory,
            variable_manager=variable_manager,
            loader=loader,
            passwords=passwords,
            stdout_callback=callback,
        )

        # create play
        play_inst = play.Play().load(
            play_source, variable_manager=variable_manager, loader=loader
        )

        # actually run it
        try:
            tqm.run(play_inst)
        finally:
            tqm.cleanup()

        # Handling errors
        failed_hosts = []
        unreachable_hosts = []
        for r in results:
            if r.status == STATUS_UNREACHABLE:
                unreachable_hosts.append(r)
            if r.status == STATUS_FAILED:
                failed_hosts.append(r)

        if len(failed_hosts) > 0:
            logger.error("Failed hosts: %s" % failed_hosts)
            if not on_error_continue:
                raise EnosFailedHostsError(failed_hosts)
        if len(unreachable_hosts) > 0:
            logger.error("Unreachable hosts: %s" % unreachable_hosts)
            if not on_error_continue:
                raise EnosUnreachableHostsError(unreachable_hosts)

        return results

    def ansible_run(
        self,
        playbooks: List[str],  # Path ?
        extra_vars=None,
        tags=None,
        on_error_continue=False,
        basedir=".",
    ):
        return _ansible_run(
            self.hosts,
            playbooks,
            extra_vars=extra_vars,
            tags=tags,
            on_error_continue=on_error_continue,
            basedir=basedir,
        )

    def wait_ssh(self, retries: int = 100, interval: int = 30) -> None:
        """Wait for all the machines to be ssh-reachable

        Let Ansible initiates a communication and retries if needed.

        Args:
            roles: Roles to wait for
            retries: Number of time we'll be retrying an SSH connection
            interval: Interval to wait in seconds between two retries

        Raises:
            EnosSSHNotReady: If some hosts can't be joined over SSH
        """
        for i in range(0, retries):
            try:
                with self.actions(gather_facts=False, on_error_continue=False) as act:
                    # We use the raw module because we can't assumed at this point that
                    # python is installed
                    act.raw("hostname")
                break
            except EnosUnreachableHostsError as e:
                logger.info("Hosts unreachable: %s " % e.hosts)
                logger.info("Retrying... %s/%s" % (i + 1, retries))
                time.sleep(interval)
        else:
            raise EnosSSHNotReady("Maximum retries reached")

    def actions(
        self,
        *,
        pattern_hosts: str = "all",
        extra_vars: Optional[MutableMapping[Any, Any]] = None,
        on_error_continue: bool = False,
        gather_facts: Union[str, bool] = True,
        priors: Optional[List["play_on"]] = None,
        run_as: Optional[str] = None,
    ):
        return play_on(
            self.hosts,
            pattern_hosts=pattern_hosts,
            extra_vars=extra_vars,
            on_error_continue=on_error_continue,
            gather_facts=gather_facts,
            priors=priors,
            run_as=run_as,
        )


def _ansible_run(
    hosts: HostInventory,
    playbooks: List[str],  # Path ?
    extra_vars=None,
    tags=None,
    on_error_continue=False,
    basedir=".",
):
    """Run Ansible.

        Args:
            playbooks (list): list of paths to the playbooks to run
            inventory_path (str): path to the hosts file (inventory)
            extra_var (dict): extra vars to pass
            tags (list): list of tags to run
            on_error_continue(bool): Don't throw any exception in case a host is
                unreachable or the playbooks run with errors

        Raises:
            :py:class:`enoslib.errors.EnosFailedHostsError`: if a task returns an
                error on a host and ``on_error_continue==False``
            :py:class:`enoslib.errors.EnosUnreachableHostsError`: if a host is
                unreachable (through ssh) and ``on_error_continue==False``
    """

    inventory, variable_manager, loader = _load_defaults(
        hosts=hosts, extra_vars=extra_vars, tags=tags, basedir=basedir
    )
    passwords = {}
    for path in playbooks:
        logger.info("Running playbook %s with vars:\n%s" % (path, extra_vars))
        pbex = PlaybookExecutor(
            playbooks=[path],
            inventory=inventory,
            variable_manager=variable_manager,
            loader=loader,
            passwords=passwords,
        )

        code = pbex.run()
        stats = pbex._tqm._stats
        hosts = stats.processed.keys()
        result = [{h: stats.summarize(h)} for h in hosts]
        results = {"code": code, "result": result, "playbook": path}
        print(results)

        failed_hosts = []
        unreachable_hosts = []

        for h in hosts:
            t = stats.summarize(h)
            if t["failures"] > 0:
                failed_hosts.append(h)

            if t["unreachable"] > 0:
                unreachable_hosts.append(h)

        if len(failed_hosts) > 0:
            logger.error("Failed hosts: %s" % failed_hosts)
            if not on_error_continue:
                raise EnosFailedHostsError(failed_hosts)
        if len(unreachable_hosts) > 0:
            logger.error("Unreachable hosts: %s" % unreachable_hosts)
            if not on_error_continue:
                raise EnosUnreachableHostsError(unreachable_hosts)


class play_on(object):
    """A context manager to manage a sequence of Ansible module calls."""

    def __init__(
        self,
        hosts: HostInventory,
        *,
        pattern_hosts: str = "all",
        extra_vars: Optional[MutableMapping[Any, Any]] = None,
        on_error_continue: bool = False,
        gather_facts: Union[str, bool] = True,
        priors: Optional[List["play_on"]] = None,
        run_as: Optional[str] = None,
    ):
        """Constructor.

        Args:
            pattern_hosts: pattern to describe ansible hosts to target.
                see https://docs.ansible.com/ansible/latest/intro_patterns.html
            inventory_path: inventory to use
            roles: roles as returned by :py:meth:`enoslib.infra.provider.Provider.init`
            extra_vars: extra_vars to use
            on_error_continue: don't throw any exception in case a host
                is unreachable or the playbooks run with errors
            gather_facts: controls how the facts will be gathered.
                - True    -> Gathers facts of :py:attr:`pattern_hosts` hosts.
                - False   -> Does not gather facts.
                - pattern -> Gathers facts of `pattern` hosts.
            priors: tasks in each prior will be prepended in the playbook
            run_as: A shortcut that injects become and become_user to each task.
                    become* at the task level has the precedence over this parameter


        Examples:

            - Minimal snippet:

                .. code-block:: python

                    with play_on(roles=roles) as t:
                        t.apt(name=["curl", "git"], state="present")
                        t.shell("which docker || (curl get.docker.com | sh)")
                        t.docker_container(name="nginx", state="started")

            - Complete example with fact_gathering

                .. literalinclude:: examples/run_play_on.py
                    :language: python
                    :linenos:

        Hint
            - Module can be run asynchronously using the corresponding Ansible options
            Note that not all the modules support asynchronous execution.

            - Note that the actual result isn't available in the result file but will
            be available through a file specified in the result object.

            - Any ansible module can be called using the above way. You'll need to
            refer to the module reference documentation to find the corresponding
            kwargs to use.
        """
        self.hosts = hosts
        self.pattern_hosts = pattern_hosts
        self.extra_vars = extra_vars if extra_vars is not None else {}
        self.on_error_continue = on_error_continue
        self.priors = priors if priors is not None else []

        # Handle modification of task level kwargs
        if run_as is not None:
            self.kwds = dict(become=True, become_user=run_as)
        else:
            self.kwds = {}

        # Will hold the tasks of the play corresponding to the sequence
        # of module call in this context
        self._tasks: List[Mapping[Any, Any]] = []
        if self.priors:
            for prior in self.priors:
                self._tasks.extend(prior._tasks)

        # Handle gather_facts
        self.gather_facts = gather_facts

    def __enter__(self):
        return self

    def __exit__(self, *args):
        gather_source = dict(hosts=[], gather_facts=False, tasks=[])
        play_source = dict(
            hosts=self.pattern_hosts, tasks=self._tasks, gather_facts=False
        )

        if isinstance(self.gather_facts, str):
            gather_source.update(hosts=self.gather_facts, gather_facts=True)
            playbook = [gather_source, play_source]
        elif self.gather_facts:
            gather_source.update(hosts=self.pattern_hosts, gather_facts=True)
            playbook = [gather_source, play_source]
        else:
            gather_source.update(gather_facts=False)
            playbook = [play_source]

        logger.debug(playbook)

        # Generate a playbook and run it
        with tempfile.NamedTemporaryFile("w", buffering=1, dir=os.getcwd()) as _pb:
            content = yaml.dump(playbook)
            _pb.write(content)
            logger.debug("Generated playbook")
            logger.debug(content)
            _ansible_run(
                self.hosts,
                [_pb.name],
                extra_vars=self.extra_vars,
                on_error_continue=self.on_error_continue,
            )

    def __getattr__(self, module_name):
        """Providers an handy way to use ansible module from python.

        """

        def _f(**kwargs):
            display_name = kwargs.pop("display_name", "__calling__ %s" % module_name)
            task = {"name": display_name}
            _kwds = copy.copy(self.kwds)
            _kwds.update(kwargs)
            top_args, module_args = _split_args(**_kwds)
            task.update(top_args)
            task.update({module_name: module_args})
            self._tasks.append(task)

        def _shell_like(command, **kwargs):
            display_name = kwargs.pop("display_name", command)
            task = {"name": display_name, module_name: command}
            _kwds = copy.copy(self.kwds)
            _kwds.update(kwargs)
            top_args, module_args = _split_args(**_kwds)
            task.update(top_args)
            if module_args:
                task.update(args=module_args)
            self._tasks.append(task)

        if module_name in ["command", "shell", "raw"]:
            return _shell_like
        return _f


class _MyCallback(CallbackModule):

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "mycallback"

    def __init__(self, storage):
        super(_MyCallback, self).__init__()
        self.storage = storage
        self.display_ok_hosts = True
        self.display_skipped_hosts = True
        self.display_failed_stderr = True
        # since 2.9
        self.set_option("show_per_host_start", True)

    def _store(self, result, status):
        record = _AnsibleExecutionRecord(
            host=result._host.get_name(),
            status=status,
            task=result._task.get_name(),
            payload=result._result,
        )
        self.storage.append(record)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        super(_MyCallback, self).v2_runner_on_failed(result)
        self._store(result, STATUS_FAILED)

    def v2_runner_on_ok(self, result):
        super(_MyCallback, self).v2_runner_on_ok(result)
        self._store(result, STATUS_OK)

    def v2_runner_on_skipped(self, result):
        super(_MyCallback, self).v2_runner_on_skipped(result)
        self._store(result, STATUS_SKIPPED)

    def v2_runner_on_unreachable(self, result):
        super(_MyCallback, self).v2_runner_on_unreachable(result)
        self._store(result, STATUS_UNREACHABLE)


# NOTE(msimonin): legacy code ahead
# There was a time where everything was dict
def _map_device_on_host_networks(networks: NetworkInventory, devices):
    """Decorate each networks with the corresponding nic name."""
    result = []
    for device in devices:
        match_for_device = False
        for role, ntxs in networks.iter_roles():
            # find the first matching network
            for network in ntxs:
                ip_set = IPSet([network.cidr])
                if "ipv4" not in device:
                    continue
                ips = device["ipv4"]
                if not isinstance(ips, list):
                    ips = [ips]
                if len(ips) < 1:
                    continue
                # NOTE(msimonin): we only consider the first IP address
                # associated to the device
                # somehow a limitation
                ip = IPAddress(ips[0]["address"])
                if ip in ip_set:
                    # that's a match, the device has an ip in the current network
                    match_for_device = True
                    _n = network.to_dict()
                    _n["device"] = device["device"]
                    result.append(_n)
                    break
            if match_for_device:
                break
    # list of concrete network for the host ie which device is associated to
    # which network
    return result


def _update_hosts(hosts: HostInventory, facts, extra_mapping=None):
    # Update every hosts in roles
    # NOTE(msimonin): due to the deserialization
    # between phases, hosts in rsc are unique instance so we need to update
    # every single host in every single role
    _hosts = copy.deepcopy(hosts)
    extra_mapping = extra_mapping or {}
    for role, hs in _hosts.iter_roles():
        for host in hs:
            networks = facts[host.alias]["networks"]
            enos_devices = []
            host.extra.update(extra_mapping)
            for network in networks:
                device = network["device"]
                if device:
                    for role in get_roles_as_list(network):
                        # backward compatibility:
                        # network_role=eth_name
                        host.extra.update({role: device})
                        # we introduce some shortcuts (avoid infinite ansible
                        # templates) in other words, we sort of precompute them
                        # network_role_dev=eth_name
                        # network_role_ip=ip
                        #
                        # Use case:
                        # - node1 has eth1 for role: r1,
                        # - node2 has eth2 for role: r2
                        # the conf in node2 must point to the ip of eth1 in
                        # node1 node2 can use hostvars[node1].r1_ip as a
                        # template Note this can happen often in g5k between
                        # nodes of different clusters
                        host.extra.update({"%s_dev" % role: device})
                        key = "ansible_%s" % device
                        ip = facts[host.alias][key]["ipv4"]["address"]
                        host.extra.update({"%s_ip" % role: ip})

                    enos_devices.append(device)

            # Add the list of devices in used by Enos
            host.extra.update({"enos_devices": enos_devices})
    return _hosts
