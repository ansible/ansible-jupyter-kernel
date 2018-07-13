FROM centos:7

ADD https://github.com/krallin/tini/releases/download/v0.14.0/tini /tini

# Install Ansible Jupyter Kernel
RUN yum -y install epel-release  && \
    yum -y install ansible python-psutil python-pip bzip2 python-crypto openssh openssh-clients gcc python-devel.x86_64 && \
    localedef -c -i en_US -f UTF-8 en_US.UTF-8 && \
    chmod +x /tini && \
    pip install --no-cache-dir wheel psutil && \
    rm -rf /var/cache/yum

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8

ENTRYPOINT ["/tini", "--"]
WORKDIR /
CMD /entrypoint.sh
ADD utils/entrypoint.sh /entrypoint.sh
ADD notebooks /notebooks
ADD tests /tests
RUN chmod 755 /entrypoint.sh && \
    chmod g+w /etc/passwd && \
    pip install --no-cache-dir ansible_kernel==0.5.0 && \
    python -m ansible_kernel.install
EXPOSE 8888
