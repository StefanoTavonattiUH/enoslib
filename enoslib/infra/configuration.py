import copy
import jsonschema
from typing import Dict, Optional, Any, Union

class _Configuration():

    def _filter_args_repr(self, kv):
        return kv

    def _top_level_kv(self):
        kv = dict([[k, getattr(self, k)] for k in self.__dict__.keys() if not k.startswith("_")])
        # deal with str class e.g
        kv = self._filter_args_repr(kv)
        return kv

    def __repr__(self):
        table = self._build_table_attrs()
        return table.get_string()

    def _repr_html_(self):
        table = self._build_table_attrs()
        return table.get_html_string()

    def _build_table_attrs(self):
        from prettytable import PrettyTable

        # first general settings
        table = PrettyTable(["Key", "Value"])
        for k, v in self._top_level_kv().items():
            table.add_row([k, v])
        return table

class BaseMachineConfiguration(_Configuration):
    pass

class BaseNetworkConfiguration(_Configuration):
    pass

class BaseConfiguration(_Configuration):
    """Base class for all the provider configuration object.

    This should be used as it is.
    """

    # Setting this is defered to the inherited classes
    _SCHEMA: Optional[Dict[Any, Any]] = None

    def __init__(self):
        # A configuration has a least these two
        self.machines = []
        self.networks = []

        # Filling up with the right machine and network
        # constructor is deferred to the sub classes.
        self._machine_cls = str
        self._network_cls = str

    @classmethod
    def from_dictionnary(cls, dictionnary, validate=True):
        """Alternative constructor. Build the configuration from a
        dictionnary."""
        pass

    @classmethod
    def from_settings(cls, **kwargs):
        """Alternative constructor. Build the configuration from a
        the kwargs."""
        self = cls()
        self.set(**kwargs)
        return self

    @classmethod
    def validate(cls, dictionnary):
        jsonschema.validate(dictionnary, cls._SCHEMA)

    def to_dict(self):
        return {}

    def finalize(self):
        d = self.to_dict()
        self.validate(d)
        return self

    def set(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        return self

    def add_machine_conf(self, machine):
        self.machines.append(machine)
        return self

    def add_machine(self, *args, **kwargs):
        self.machines.append(self._machine_cls(*args, **kwargs))
        return self

    def add_network_conf(self, network):
        self.networks.append(network)
        return self

    def add_network(self, *args, **kwargs):
        self.networks.append(self._network_cls(*args, **kwargs))
        return self

    def _filter_args_repr(self, kv):
        _kv = copy.deepcopy(kv)
        _kv.pop("machines")
        _kv.pop("networks")
        return _kv

    def _repr_html_(self):
        # top level repr
        s = super()._repr_html_()
        s = "<h1>Général</h1>" + s

        # machines repr
        from prettytable import PrettyTable
        table_m = PrettyTable()
        for m in self.machines:
            kv = m._top_level_kv()
            table_m.field_names = kv.keys()
            table_m.add_row(kv.values())

        if self.machines:
            s += "<h1>Machines</h1>" + table_m.get_html_string()

        # networks repr
        from prettytable import PrettyTable
        table_n = PrettyTable()
        for n in self.networks:
            # there are cases where n is str...
            # We'd want to encapsulate this in an POPO and avoid this hack
            fun = getattr(n, "_top_level_kv", None)
            if fun is not None:
                kv = n._top_level_kv()
                table_n.field_names = kv.keys()
                table_n.add_row(kv.values())
            else:
                table_n.field_names = ["id"]
                table_n.add_row([n])
        if self.networks:
            s += "<h1>Networks</h1>" + table_n.get_html_string()

        return s