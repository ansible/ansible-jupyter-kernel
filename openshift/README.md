
## Deploying Ansible Jupyter on OpenShift

Create a new project.
```
oc new-project kernel
```

Add the template to the project,

```
oc create -f https://raw.githubusercontent.com/ansible/ansible-jupyter-kernel/master/openshift/openshift-template.yaml
```

And finally deploy.

```
oc new-app --template ansible-jupyter-kernel
```


## Retrieve the login token

```
oc logs -f dc/ansible-jupyter
```

## Get the route

```
oc get route ansible-jupyter --template '{{ (index (.status.ingress) 0).host }}'
```

