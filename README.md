# Ansible Collection - sbercloud.dynamic_inventory

1. create inventory file sbercloud_vm_inventory.yml with contents:
```yaml
plugin: sbercloud.dynamic_inventory.sbercloud_vm_inventory
project_id: put sbercloud project id here
```
2. set env variables:
```bash
export access_key_id=ACCESS_KEY_ID
export secret_access_key=SECRET_ACCESS_KEY
```
3. run
```bash
ansible-inventory -i sbercloud_vm_inventory.yml --list 
```
