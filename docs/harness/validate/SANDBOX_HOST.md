# Docker + gVisor sandbox host (Arch / Omarchy)

Sandbox PoC is **off** unless you opt in: `vf init --sandbox-poc`, or New audit **Sandbox PoC one-shot**. Init and campaign start (`vf` / dashboard Start / campaign `start`) refuse when this process cannot use the Docker API, or when `select_isolation` would be `sandbox_unavailable`. A later `validate_poc` still fails closed if the sandbox disappears; that does not set `confirmed` and does not clear needs-human.

Use the host directory `~/Projects/OSSvulnHunting` in notes and path templates (that casing).

## Install

1. Enable the daemon: `sudo systemctl enable --now docker`.
2. `sudo usermod -aG docker "$USER"`.
3. Log out and back in completely. `newgrp docker` only covers that shell. The dashboard and Ralph keep the old group list until the login session is new. VulnForge checks effective GIDs (`os.getgroups()`), not `/etc/group` alone.
4. `yay -S gvisor-bin`
5. `sudo runsc install` so `docker info` lists runtime `runsc`. If runsc misbehaves under the systemd cgroup driver, set `"exec-opts": ["native.cgroupdriver=cgroupfs"]` in `/etc/docker/daemon.json` and restart docker.
6. `docker pull python:3.12.8-slim-bookworm`
7. `docker run --runtime=runsc hello-world`

## Check before opting in

`probe_host()["docker"]` is true only when this process's `docker info` succeeds (daemon up and authorized). `docker_cli` can be true while `docker` is false: CLI present, API unusable (socket permission denied, daemon inactive, non-zero exit, timeout). Runtimes stay empty in that case, and `select_isolation` stays `sandbox_unavailable`.

Opt in only after `select_isolation` is a microVM or gVisor `runsc`. The ladder is unchanged: microVM, then gVisor, then refuse. There is no host or plain-runc fallback.

## After git pull

Stop the dashboard process and start it again (`vf dashboard`) so it loads the pulled code, including the static UI.

MicroVM / Firecracker install is a separate path. This pack does not cover `vf pause` / `vf resume` CLI parity.
