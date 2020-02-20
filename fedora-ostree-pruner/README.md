# fedora-ostree-pruner

Source code that prunes OSTree repos based on policy.

# Deploying in Fedora

The [playbook](https://pagure.io/fedora-infra/ansible/blob/main/f/playbooks/openshift-apps/fedora-ostree-pruner.yml)
and [supporting files](https://pagure.io/fedora-infra/ansible/blob/main/f/roles/openshift-apps/fedora-ostree-pruner)
for deploying to Fedora's OpenShift Instance are in the
[Fedora Infra Ansible repo](https://pagure.io/fedora-infra/ansible).

The application can be deployed by people with appropriate permissions by
executing:

```
[localhost]$ ssh batcave01.iad2.fedoraproject.org
[batcave01]$ sudo rbac-playbook openshift-apps/fedora-ostree-pruner.yml
```

The application will then be running in Fedora OpenShift instances:

- [PROD](https://console-openshift-console.apps.ocp.fedoraproject.org/k8s/ns/fedora-ostree-pruner)
- [STAGE](https://console-openshift-console.apps.ocp.stg.fedoraproject.org/k8s/ns/fedora-ostree-pruner)

If you have appropriate permissions you'll be able to view them in the
OpenShift web interface.

To limit executing playbooks against `prod` or `staging` you can use
`-l os_control` or `-l os_control_stg`.

To take down the application completely:

```
[localhost]$ ssh batcave01.iad2.fedoraproject.org
[batcave01]$ sudo rbac-playbook -t delete openshift-apps/fedora-ostree-pruner.yml
```
