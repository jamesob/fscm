FROM debian:bookworm

RUN apt-get update && apt-get install -y python3 openssh-server sudo && /usr/bin/ssh-keygen -A && \
  ( echo 'root:root' | chpasswd ) && \
  sed -i -e 's/^UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config && \
  sed -i -e 's/.*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config && \
  useradd -ms /bin/bash -G sudo user && \
  ( echo 'user:user' | chpasswd ) && \
  mkdir /home/user/.ssh/ && \
  ( echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ4RUgchNhBKUIVxJ7WS8MeHy7Ss3jUvuijbQWxNuGWf james@fido' >> /home/user/.ssh/authorized_keys ) && \
  mkdir -p /run/sshd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
