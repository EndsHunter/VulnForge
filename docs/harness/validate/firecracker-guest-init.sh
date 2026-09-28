#!/bin/sh
# Reference guest init for direct Firecracker one-shot (not installed on the host).
# Rootfs should use this as /init, or an equivalent that honors vf.cmd=.
# Boot args include pci=off and vf.cmd=<base64 of the PoC command>.
# No network device is configured by the host plan.
set -eu
cmd=""
for tok in $(cat /proc/cmdline); do
  case "$tok" in
    vf.cmd=*) cmd=$(printf '%s' "${tok#vf.cmd=}" | base64 -d) ;;
  esac
done
if [ -z "$cmd" ]; then
  echo "VF_POC_EXIT=127 missing vf.cmd"
  exit 127
fi
# Evidence is not bind-mounted. The command runs inside this rootfs.
sh -c "$cmd"
echo "VF_POC_EXIT=$?"
