import copy
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import InitVar, dataclass, field
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv6Address,
    IPv6Interface,
    ip_address,
    ip_interface,
)
from netaddr import EUI
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

NetworkType = Union[bytes, int, Tuple, str]
AddressType = Union[bytes, int, Tuple, str]
AddressInterfaceType = Union[IPv4Address, IPv6Address]


def _ansible_map_network_device(
    provider_nets: List["Network"], devices: List[Dict]
) -> List[Tuple["Network", "IPAddress"]]:
    """Map networks to ansible devices."""
    matches = []
    for provider_net in provider_nets:
        for device in devices:
            versions = ["ipv4", "ipv6"]
            for version in versions:
                if version not in device:
                    continue
                ips = device[version]
                if not isinstance(ips, list):
                    ips = [ips]
                if len(ips) < 1:
                    continue
                for ip in ips:
                    host_addr = IPAddress.from_ansible(
                        ip, roles=provider_net.roles, device=device["device"]
                    )
                    if host_addr.ip in provider_net.network:
                        # found a map between a device on the host and a network
                        matches.append((provider_net, host_addr))
    return matches


class Network(ABC):
    """Base class for the library level network abstraction.

    When one calls init on a provider, one takes ownership on nodes and
    networks. This class reflect one network owned by the user for the
    experiment lifetime. IPv4 and IPv6 networks can be reprensented by such
    object.
    Provider can inherit from this class or use the
    :py:class:`DefaultNetwork` class which provides a good enough
    implementation in most cases.
    """
    def __init__(self, roles: List[str], address: NetworkType):
        self.roles = roles
        # accept cidr but coerce to IPNetwork
        self.network = ip_interface(address).network

    @property
    @abstractmethod
    def gateway(self) -> Optional[AddressInterfaceType]:
        ...

    @property
    @abstractmethod
    def dns(self) -> Optional[AddressInterfaceType]:
        ...

    @property
    @abstractmethod
    def has_free_ips(self):
        return False

    @property
    @abstractmethod
    def free_ips(self) -> Iterable[AddressInterfaceType]:
        yield from ()

    @property
    @abstractmethod
    def has_free_macs(self):
        return False

    @property
    @abstractmethod
    def free_macs(self) -> Iterable[str]:
        yield from ()


class DefaultNetwork(Network):
    """Good enough implementation of Network for most situations.

    Provides pooling for contiguous ips and/or macs.
    Support IPv4 and IPv6.

    Args:
        roles: list of roles to assign to this role
        address: network address (as in ipaddress.ip_interface)
        gateway: (optionnal) the gateway for this network
        dns: (optional) the dns address
        ip_start: (optional) first ip in the ip pool
        ip_end: (optional) last ip in the ip pool
        mac_start: (optional) first mac in the mac pool
        mac_end: (optional) last mac in the mac pool
    """
    def __init__(
        self,
        roles: List[str],
        address: NetworkType,
        gateway: Optional[str] = None,
        dns: Optional[str] = None,
        ip_start: Optional[AddressType] = None,
        ip_end: Optional[AddressType] = None,
        mac_start: str = None,
        mac_end: str = None,
    ):

        super().__init__(roles=roles, address=address)
        self._gateway = None
        if gateway is not None:
            self._gateway = ip_address(gateway)
        self._dns = None
        if self._dns is not None:
            self._dns = ip_address(dns)
        self.pool_start = None
        if ip_start is not None:
            self.pool_start = ip_address(ip_start)
        if ip_end is not None:
            self.pool_end = ip_address(ip_end)
        self.pool_mac_start: Optional[EUI] = None
        if mac_start is not None:
            self.pool_mac_start = EUI(mac_start)
        self.pool_mac_end: Optional[EUI] = None
        if mac_end is not None:
            self.pool_mac_end = EUI(mac_end)

    @property
    def gateway(self) -> Optional[AddressInterfaceType]:
        return self._gateway

    @property
    def dns(self) -> Optional[AddressInterfaceType]:
        return self._dns

    @property
    def has_free_ips(self):
        return self.pool_start and self.pool_end and self.pool_start < self.pool_end

    @property
    def free_ips(self) -> Iterable[AddressInterfaceType]:
        if self.has_free_ips:
            assert self.pool_start is not None
            assert self.pool_end is not None
            for i in range(int(self.pool_start), int(self.pool_end)):
                yield ip_address(i)
        yield from ()

    @property
    def has_free_macs(self):
        return (
            self.pool_mac_start
            and self.pool_mac_end
            and self.pool_mac_start < self.pool_mac_end
        )

    @property
    def free_macs(self) -> Iterable[EUI]:
        if self.has_free_macs:
            assert self.pool_mac_start is not None
            assert self.pool_mac_end is not None
            for item in range(int(self.pool_mac_start), int(self.pool_mac_end)):
                yield EUI(item)
        yield from ()


@dataclass(unsafe_hash=True)
class IPAddress(object):
    """Representation of an address on a node.

    Usually the same ip_address can't be assigned twice.
    So equality and hash are based only on the ip field.
    """

    address: InitVar[Union[bytes, int, Tuple, str]]
    roles: List[str] = field(compare=False, hash=False)
    device: str = field(compare=False, hash=False)

    # computed
    ip: Optional[Union[IPv4Interface, IPv6Interface]] = field(
        default=None, init=False, compare=True, hash=True
    )

    def __post_init__(self, address):
        # transform to ip interface
        self.ip = ip_interface(address)

    @classmethod
    def from_ansible(cls, d: Dict, roles: List[str], device: str):
        """Build an IPAddress from ansible fact.

        Ansible fact corresponding section can be:
        - ipv4: {"address": ..., "netmask": ..., "broadcast": ..., }
        - ipv6: {"address": ..., "prefix": ..., "scope": ...}
        """
        keys_1 = {"address", "netmask"}
        keys_2 = {"address", "prefix"}
        if keys_1.issubset(d.keys()):
            # there's a bug/feature in early python3.7, and the second argument
            # is actually the prefix length
            # https://bugs.python.org/issue27860
            # cls((d["address"], d["netmask"])), roles, device)
            return cls(f"{d['address']}/{d['netmask']}", roles, device)
        elif keys_2.issubset(d.keys()):
            return cls(f"{d['address']}/{d['prefix']}", roles, device)
        else:
            raise ValueError(f"Nor {keys_1} not {keys_2} found in the dictionnary")


@dataclass(unsafe_hash=True)
class Host(object):
    """Abstract unit of computation.

    A Host is anything EnosLib can access (e.g using SSH) to and run shell
    commands on. It is an abstraction notion of unit of computation that can
    be bound to bare-metal machines, virtual machines, or containers.


    Note:

        Internally EnOSlib is using Ansible to connect to the remote hosts.
        By default SSH is used but it isn't the only connection method
        supported. You can change the connection method to fit your needs by
        setting the `ansible_connection` key in the extra field (and other
        options if needed).
        Ref: https://docs.ansible.com/ansible/latest/plugins/connection.html

    Args:
        address: host will be reached at this address (using SSH by default).
        alias: a human readable alias
        user: user to connect with (e.g using SSH)
        keyfile: keyfile to use to authenticate (e.g when using SSH)
        port: port to connect to (e.g using SSH)
        extra: dictionnary of options. Will be passed to Ansible as host_vars.
        extra_adddresses: list of network addresses configured on this host.
            can be synced with the :py:func:`enoslib.api.sync_network_info`.

    Note:
        In the future we'd like the provider to populate the extra_addresses
        to get a consistent initial representation of the hosts.
    """

    address: str
    alias: Optional[str] = field(default=None)
    user: Optional[str] = None
    keyfile: Optional[str] = None
    port: Optional[int] = None
    # Two Hosts have the same hash if we can SSH on each of them in
    # the same manner (don't consider extra info in `__hash__()` that
    # are added, e.g., by enoslib.api.sync_network_info).
    extra: Dict = field(default_factory=dict, hash=False)
    # Hold a list of known ip addresses
    # - discover_network can set this for you
    # - also there's a plan to make the provider fill that for you when
    #   possible (e.g in G5K we can use the REST API)
    extra_addresses: Set[IPAddress] = field(default_factory=set, hash=False)

    def __post_init__(self):
        if not self.alias:
            self.alias = self.address

        # we make a copy to avoid to share the reference to extra outside
        # see for example https://gitlab.inria.fr/discovery/enoslib/-/issues/74
        if self.extra is not None:
            self.extra = copy.deepcopy(self.extra)

        if self.extra_addresses is None:
            self.extra_addresses = set()
        self.extra_addresses = set(self.extra_addresses)

    def to_dict(self):
        d = dict(
            address=self.address,
            alias=self.alias,
            user=self.user,
            keyfile=self.keyfile,
            port=self.port,
            extra=self.extra,
            extra_addresses=list(self.extra_addresses),
        )
        return copy.deepcopy(d)

    def add_address(self, address: IPAddress):
        """Add an ip address to this host.

        If the IP already exists, replace it with the new value.
        Mutate self, since it add/update the list of network addresses

        Args:
            address: The ip address to add (or update)
        """
        try:
            self.extra_addresses.remove(address)
        except KeyError:
            pass
        self.extra_addresses.add(address)

    def set_addresses_from_ansible(
        self, networks: List[Network], host_facts: Dict, clear: bool = True
    ):
        """Set the ip_addresses based on ansible fact.

        Mutate self, since it add/update the list of network addresses
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

        if clear:
            self.extra_addresses = set()
        matches = _ansible_map_network_device(networks, get_devices(host_facts))
        for _, addr in matches:
            self.add_address(addr)

    def get_network_roles(self):
        """Index the address by network roles."""
        roles = defaultdict(list)
        for address in self.extra_addresses:
            for role in address.roles:
                roles[role].append(address)
        return roles

    @classmethod
    def from_dict(cls, d):
        _d = copy.deepcopy(d)
        address = _d.pop("address")
        return cls(address, **_d)

    def to_host(self):
        """Copy or coerce to a Host."""
        return Host(
            self.address,
            alias=self.alias,
            user=self.user,
            keyfile=self.keyfile,
            port=self.port,
            extra=self.extra,
        )

    def __str__(self):
        args = [
            self.alias,
            "address=%s" % self.address,
            "user=%s" % self.user,
            "keyfile=%s" % self.keyfile,
            "port=%s" % self.port,
            "extra=%s" % self.extra,
        ]
        return "Host(%s)" % ", ".join(args)
