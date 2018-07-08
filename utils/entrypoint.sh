#!/usr/bin/env bash

# In OpenShift, containers are run as a random high number uid
# that doesn't exist in /etc/passwd, but Ansible module utils
# require a named user. So if we're in OpenShift, we need to make
# one before Ansible runs.
if [ `id -u` -ge 500 ]; then
    echo "runner:x:`id -u`:`id -g`:,,,:/runner:/bin/bash" > /tmp/passwd
    cat /tmp/passwd >> /etc/passwd
    rm /tmp/passwd
fi
cd /notebooks
jupyter-notebook --ip 0.0.0.0 --allow-root --no-browser
