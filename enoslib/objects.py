import copy
from dataclasses import dataclass, field
from typing import Generic, Generator, List, Union, Tuple, TypeVar

# TODO remove this
from enoslib.host import Host as EnoslibHost
from enoslib.utils import ReprMixin


class Host(ReprMixin, EnoslibHost):
    pass


# TODO:
#  - use IPv4 object here (netaddr)
#  - handle ipv6 network someday
@dataclass
class Network(ReprMixin):
    cidr: str
    start: str = None
    end: str = None
    dns: str = None
    gateway: str = None

    def to_dict(self):
        return copy.deepcopy(self.__dict__)


IElem = TypeVar("IElem")


class AtomicInventory(Generic[IElem]):
    def add(self, roles: List[str], elem: IElem):
        pass

    def iter_roles(self) -> Generator[Tuple[str, List[IElem]], None, None]:
        pass

    def __repr__(self):
        table = self._build_table_attrs()
        return table.get_string()

    def _repr_html_(self):
        table = self._build_table_attrs()
        return table.get_html_string()

    def _build_table_attrs(self):
        from prettytable import PrettyTable

        table = PrettyTable()
        for role, items in self.iter_roles():
            for item in items:
                d = item.to_dict()
                table.field_names = ["role"] + list(d.keys())
                values = [role] + list(d.values())
                table.add_row(values)
        return table


class HostInventory(AtomicInventory):
    pass


class NetworkInventory(AtomicInventory):
    """NOTE(msimonin): There's nevertheless a diff with HostInventory
        I don't think a 2 different network with the same roel can coexist
    """

    pass


class InMemInventory(Generic[IElem], AtomicInventory):
    def __init__(self):
        self.backend = {}

    def add(self, roles: List[str], elem: IElem):
        # we mimic the legacy behaviour for now
        # ie make as many references as roles for the same machines
        # that's bad but should prevent things to break for now as
        for role in roles:
            self.backend.setdefault(role, []).append(copy.deepcopy(elem))

    def iter_roles(self) -> Generator[Tuple[str, List[IElem]], None, None]:
        for role, elems in self.backend.items():
            yield role, elems

    def __getitem__(self, key: str):
        return self.backend[key]

    def __setitem__(self, key: str, value: Union[IElem, List[IElem]]):
        if isinstance(value, str):
            self.add([key], [value])
        elif isinstance(value, list):
            self.add([key], value)
        else:
            raise ValueError("Item must be a Host or a List of Host")


class InMemHostInventory(InMemInventory[EnoslibHost], HostInventory):
    pass


class InMemNetworkInventory(InMemInventory[Network], NetworkInventory):
    pass


class Inventory:
    """Facade to concrete resources."""

    def __init__(self, hosts: HostInventory, networks: NetworkInventory):
        self.hosts = hosts
        self.networks = networks

    def hosts_inventory(self):
        return self.hosts

    def networks_inventory(self):
        return self.networks

    def add_host(self, roles: List[str], host: Host):
        self.hosts.add(roles, host)

    def add_network(self, roles: List[str], network: Network):
        self.networks.add(roles, network)

    def get_hosts(self, pattern: str = "*"):
        """Get all the hosts matching the pattern.

        Args:
            roles: the roles as returned by
                :py:meth:`enoslib.infra.provider.Provider.init`
            pattern_hosts: pattern to describe ansible hosts to target.
                see https://docs.ansible.com/ansible/latest/intro_patterns.html

        Return:
            The list of hosts matching the pattern
        """
        pass

    def __repr__(self):
        hosts_table, network_tables = self._build_tables()
        return (
            hosts_table.get_string(title="Hosts")
            + "\n"
            + network_tables.get_string(title="Networks")
        )

    def _repr_html_(self):
        hosts_table, network_tables = self._build_tables()
        return hosts_table.get_html_string() + "\n" + network_tables.get_html_string()

    def _build_tables(self):
        hosts_table = self.hosts._build_table_attrs()
        networks_table = self.networks._build_table_attrs()
        return hosts_table, networks_table
