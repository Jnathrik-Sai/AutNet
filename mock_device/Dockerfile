FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt install -y openssh-server && \
    mkdir -p /var/run/sshd /root/.ssh && \
    echo 'root:cisco' | chpasswd && \
    sed -i 's/#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    echo "Welcome to mock device" > /etc/motd && \
    echo 'command="echo show version; echo Cisco IOS XR Mock Version;" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD...' >> /root/.ssh/authorized_keys && \
    chmod 600 /root/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]