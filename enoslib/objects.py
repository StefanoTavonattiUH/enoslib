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


def _build_devices(facts, networks):
    """Extract the network devices information from the facts."""
    devices = set()
    for interface in facts["ansible_interfaces"]:
        ansible_interface = "ansible_" + interface
        # filter here (active/ name...)
        if ansible_interface in facts:
            devices.add(NetDevice.sync_from_ansible(facts[ansible_interface], networks))
    return devices


class Network(ABC):
    """Base class for the library level network abstraction.

    When one calls init on a provider, one takes ownership on nodes and
    networks. This class reflect one network owned by the user for the
    experiment lifetime. IPv4 and IPv6 networks can be reprensented by such
    object.

    Providers *must* inherit from this class or the
    :py:class:`DefaultNetwork` class which provides a good enough
    implementation in most cases.

    Indeed, currently provenance (which provider created this) is encoded in
    the __class__ attribute.
    """

    def __init__(self, roles: List[str], address: NetworkType):
        self.roles = roles
        # accept cidr but coerce to IPNetwork
        self.network = ip_interface(address).network

    def __eq__(self, other) -> bool:
        if self.__class__ != other.__class__:
            return False
        return self.network == other.network

    def __hash__(self):
        return hash(self.network)

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

    Providers *must* inherit from this class.

    Args:
        roles    : list of roles to assign to this role
        address  : network address (as in ipaddress.ip_interface)
        gateway  : (optionnal) the gateway for this network
                   (as in ipaddress.ip_address)
        dns      : (optional) the dns address
                   (as in ipaddress.ip_address)
        ip_start : (optional) first ip in the ip pool
                   (as in ipaddress.ip_address)
        ip_end   : (optional) last ip in the ip pool
                   (as in ipaddress.ip_address)
        mac_start: (optional) first mac in the mac pool
                   (as in netaddr.EUI)
        mac_end  : (optional) last mac in the mac pool
                   (as in netaddr.EUI)
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
    def has_free_ips(self) -> bool:
        return (
            self.pool_start is not None
            and self.pool_end is not None
            and self.pool_start < self.pool_end
        )

    @property
    def free_ips(self) -> Iterable[AddressInterfaceType]:
        if self.has_free_ips:
            assert self.pool_start is not None
            assert self.pool_end is not None
            for i in range(int(self.pool_start), int(self.pool_end)):
                yield ip_address(i)
        yield from ()

    @property
    def has_free_macs(self) -> bool:
        return (
            self.pool_mac_start is not None
            and self.pool_mac_end is not None
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

    Usually the same ip_address can't be assigned twice. So equality and hash
    are based on the ip field. Moreover in the case where two providers
    network span the same ip range equality is also based on the network
    provenance.
    """

    address: InitVar[Union[bytes, int, Tuple, str]]
    network: Optional[Network] = field(default=None, compare=True, hash=True)

    # computed
    ip: Optional[Union[IPv4Interface, IPv6Interface]] = field(
        default=None, init=False, compare=True, hash=True
    )

    def __post_init__(self, address):
        # transform to ip interface
        self.ip = ip_interface(address)

    @property
    def roles(self):
        if self.network is not None:
            return self.network.roles
        else:
            return []

    @classmethod
    def from_ansible(cls, d: Dict, network: Optional[Network]):
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
            return cls(f"{d['address']}/{d['netmask']}", network)
        elif keys_2.issubset(d.keys()):
            return cls(f"{d['address']}/{d['prefix']}", network)
        else:
            raise ValueError(f"Nor {keys_1} not {keys_2} found in the dictionnary")


@dataclass(unsafe_hash=True)
class NetDevice(object):
    """A network device.

    Note: two NetDevices are equal iff they have the same name and all the
    addresses are equals.
    """

    name: str = field(compare=True, hash=True)
    addresses: Set[IPAddress] = field(default_factory=set, compare=True, hash=False)

    @classmethod
    def sync_from_ansible(cls, device: Dict, networks: List[Network]):
        """
            "ansible_enx106530ad1e3f": {
            "active": true,
                "device": "enx106530ad1e3f",
                "ipv4": {
                    "address": "192.168.1.14",
                    "broadcast": "192.168.1.255",
                    "netmask": "255.255.255.0",
                    "network": "192.168.1.0"
                }
                "macaddress": "10:65:30:ad:1e:3f",
                "module": "r8152",
                "mtu": 1500,
                "pciid": "2-1.2:1.0",
                "promisc": false,
                "speed": 1000,
                "type": "ether"
        }
        """
        # build all ips
        addresses = set()
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
                _net = None
                for provider_net in networks:
                    # build an IPAddress /a priori/
                    addr = IPAddress.from_ansible(ip, provider_net)
                    if addr.ip in provider_net.network:
                        _net = provider_net
                addresses.add(IPAddress.from_ansible(ip, _net))
        # addresses contains all the addresses for this devices
        # even those that doesn't correspond to an enoslib network

        # detect if that's a bridge
        if device["type"] == "bridge":
            return BridgeDevice(
                name=device["device"], addresses=addresses, bridged=device["interfaces"]
            )
        else:
            # regular "ether"
            return cls(name=device["device"], addresses=addresses)

    @property
    def interfaces(self) -> List[str]:
        return [self.name]

    def filter_addresses(
        self, networks: Optional[List[Network]] = None, include_unknown: bool = False
    ) -> List[IPAddress]:
        """Filter address based on the passed network list.

        Args:
            networks: a list of networks to further filter the request
                      If None, all the interfaces with at least one network attached
                      will be returned. This doesn't return interfaces
                      attached to network unknown from EnOSlib.
            include_unknown: True iff we want all the interface that are not
                      attached to an EnOSlib network. Ignored if ``networks`` is not
                      None.

        Return:
            A list of addresses
        """
        if networks is not None:
            # return only known addresses
            return [
                addr
                for addr in self.addresses
                for network in networks
                if addr.ip in network.network
            ]
        # return all the addresses known to enoslib (those that belong to one network)
        addresses = [addr for addr in self.addresses if addr.network is not None]
        if include_unknown:
            return addresses + [addr for addr in self.addresses if addr.network is None]
        return addresses


@dataclass(unsafe_hash=True)
class BridgeDevice(NetDevice):
    bridged: List[str] = field(default_factory=list, compare=False, hash=False)

    @property
    def interfaces(self) -> List[str]:
        """Get all the interfaces that are bridged here."""
        return self.bridged


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
    extra_devices: Set[NetDevice] = field(default_factory=set, hash=False)

    def __post_init__(self):
        if not self.alias:
            self.alias = self.address

        # we make a copy to avoid to share the reference to extra outside
        # see for example https://gitlab.inria.fr/discovery/enoslib/-/issues/74
        if self.extra is not None:
            self.extra = copy.deepcopy(self.extra)

        if self.extra_devices is None:
            self.extra_devices = set()
        self.extra_devices = set(self.extra_devices)

    def to_dict(self):
        d = dict(
            address=self.address,
            alias=self.alias,
            user=self.user,
            keyfile=self.keyfile,
            port=self.port,
            extra=self.extra,
            extra_devices=list(self.extra_devices),
        )
        return copy.deepcopy(d)

    def sync_from_ansible(
        self, networks: List[Network], host_facts: Dict, clear: bool = True
    ):
        """Set the devices based on ansible fact.s

        Mutate self, since it add/update the list of network devices
        Currently the dict must be compatible with the ansible hosts facts.
        """

        if clear:
            self.extra_devices = set()
        self.extra_devices = _build_devices(host_facts, networks)
        return self

    @property
    def netdevice_addresses(self):
        """Get all the ip_addresses associated with some roles/network"""
        return [
            (device.name, address)
            for device in self.extra_devices
            for address in device.addresses
            if address.network is not None
        ]

    @property
    def addresses(self):
        return [na[1] for na in self.netdevice_addresses]

    def filter_addresses(
        self, networks: Optional[List[Network]] = None, include_unknown=False
    ) -> List[IPAddress]:
        """Get some of the addresses assigned to this host.

        Args:
            networks: a list of networks to further filter the request
                      If None, all the interfaces with at least one network attached
                      will be returned. This doesn't return interfaces
                      attached to network unknown from EnOSlib.
            include_unknown: True iff we want all the interface that are not
                      attached to an EnOSlib network. Ignored if ``networks`` is not
                      None.

        Return:
            A list of addresses
        """
        addresses = []
        for net_device in self.extra_devices:
            addresses += net_device.filter_addresses(
                networks, include_unknown=include_unknown
            )
        return addresses

    def filter_interfaces(
        self, networks: Optional[List[Network]] = None, include_unknown=False
    ) -> List[str]:
        """Get some of the device interfaces.

        Args:
            networks: a list of networks to further filter the request
                      If None, all the interfaces with at least one network attached
                      will be returned. This doesn't return interfaces
                      attached to network unknown from EnOSlib.
            include_unknown: True iff we want all the interface that are not
                      attached to an EnOSlib network. Ignored if ``networks`` is not
                      None.

        Return:
            A list of interface names.
        """
        interfaces = []
        for net_device in self.extra_devices:
            if net_device.filter_addresses(networks, include_unknown=include_unknown):
                # at least one address in this network
                # or networks is None and we got all the known addresses
                interfaces.extend(net_device.interfaces)
        return interfaces

    def get_network_roles(self):
        """Index the address by network roles."""
        roles = defaultdict(list)
        for device, address in self.netdevice_addresses:
            for role in address.roles:
                roles[role].append((device, address))
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
            "extra_addresses=%s" % self.extra_devices,
        ]
        return "Host(%s)" % ", ".join(args)
