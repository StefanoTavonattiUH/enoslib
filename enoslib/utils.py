# -*- coding: utf-8 -*-
import os

from enoslib.errors import EnosFilePathError


def get_roles_as_list(desc):
    # NOTE(msimonin): role and roles are mutually exclusive in theory We'll fix
    # the schemas later in the mean time to not break user code let's remove
    # duplicates here
    roles = desc.get("roles", [])
    if roles:
        return roles

    role = desc.get("role", [])
    if role:
        roles = [role]

    return roles


def gen_rsc(roles):
    for _, hosts in roles.items():
        for host in hosts:
            yield host


def _check_tmpdir(tmpdir):
    if not os.path.exists(tmpdir):
        os.mkdir(tmpdir)
    else:
        if not os.path.isdir(tmpdir):
            raise EnosFilePathError("%s is not a directory" % tmpdir)
        else:
            pass

class ReprMixin:
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