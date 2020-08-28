from enoslib.infra.enos_vagrant.provider import Enos_vagrant
from enoslib.infra.enos_vagrant.configuration import Configuration
from enoslib.launcher import AnsibleLauncher

import logging

logging.basicConfig(level=logging.DEBUG)

provider_conf = {
    "resources": {
        "machines": [{
            "roles": ["control1"],
            "flavour": "tiny",
            "number": 1,
        },{
            "roles": ["control2"],
            "flavour": "tiny",
            "number": 1,
        }],
        "networks": [{"roles": ["rn1"], "cidr": "172.16.0.1/16"}]
    }
}

conf = Configuration.from_dictionnary(provider_conf)
provider = Enos_vagrant(conf)
inventory = provider.init()
launcher = AnsibleLauncher(inventory)
launcher.run_cmd("date")
# modified inventory
inventory = launcher.discover_networks()
# launcher.ansible_run(["site.yml"])
# launcher.wait_ssh()
# with launcher.actions() as act:
#    act.debug(msg="Hello")
#    act.apt(name="nginx", state="present")
# ensure_python3(inventory.host_inventory(), make_default=True)
