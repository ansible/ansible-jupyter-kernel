FROM centos:7

# Install Ansible Jupyter Kernel
RUN yum -y install epel-release  && \
    yum -y install ansible python-psutil python-pip bzip2 python-crypto openssh openssh-clients gcc python-devel.x86_64 && \
    localedef -c -i en_US -f UTF-8 en_US.UTF-8 && \
    pip install --no-cache-dir wheel psutil && \
    rm -rf /var/cache/yum

RUN pip install --no-cache-dir IPython==5.7.0
RUN pip install --no-cache-dir notebook==5.6.0rc1

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8

ENV NB_USER notebook
ENV NB_UID 1000
ENV HOME /home/${NB_USER}

RUN useradd \
    -c "Default user" \
	-d /home/notebook \
    -u ${NB_UID} \
    ${NB_USER}

COPY . ${HOME}
USER root
RUN chown -R ${NB_UID} ${HOME}

RUN pip install --no-cache-dir ansible_kernel==0.8.0 && \
    python -m ansible_kernel.install
USER ${NB_USER}
WORKDIR /home/notebook/notebooks
CMD ["jupyter", "notebook", "--ip", "0.0.0.0"]
EXPOSE 8888
