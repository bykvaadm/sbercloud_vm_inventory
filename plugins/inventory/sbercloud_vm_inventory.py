#!/usr/bin/env python3

from ansible_collections.bykvaadm.sbercloud_dynamic_inventory.plugins.module_utils.apig_sdk import (
    signer,
)

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable
import os

DOCUMENTATION = r"""
    name: bykvaadm.sbercloud_dynamic_inventory.sbercloud_vm_inventory
    plugin_type: inventory
    short_description: Returns Ansible inventory from CSV
    description: Returns Ansible inventory from CSV
    options:
      project_id:
        description: project id
        required: True
      access_key_id_env_name:
        description: access key id
        default: access_key_id
      secret_access_key_env_name:
        description: secret access key
        default: secret_access_key
"""


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    NAME = "sbercloud_vm_inventory"

    def verify_file(self, path):
        return True

    def parse(self, inventory, loader, path, cache=True):
        """
        Parses the inventory file
        """
        super(InventoryModule, self).parse(inventory, loader, path, cache=cache)

        self._read_config_data(path)

        project_id = self.get_option("project_id")
        access_key_id = os.getenv(self.get_option("access_key_id_env_name"))
        secret_access_key = os.getenv(self.get_option("secret_access_key_env_name"))

        sig = signer.Signer(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            method="GET",
            url=f"https://ecs.ru-moscow-1.hc.sbercloud.ru/v1/{project_id}/cloudservers/detail",
            headers={"X-Project-Id": project_id},
        )

        for json_servers in sig.gen_next_page():
            for server in json_servers["servers"]:
                if len(server["tags"]):
                    for tag in server["tags"]:
                        c_group = self.inventory.add_group(tag.partition("=")[2])
                        self.inventory.add_host(server["name"], c_group)
