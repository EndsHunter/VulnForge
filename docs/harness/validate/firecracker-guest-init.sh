#!/bin/sh
# Reference guest init for direct Firecracker one-shot (not installed on the host).
# Rootfs should use this as /init, or an equivalent that honors vf.cmd=.
# Boot args include pci=off. vf.cmd=drive means the command is the second
# virtio block device (/dev/vdb), not a base64 blob on the kernel cmdline.
# No network device is configured by the host plan.
set -eu
cmd=""
mode=""
for tok in $(cat /proc/cmdline); do
  case "$tok" in
    vf.cmd=*) mode=${tok#vf.cmd=} ;;
  esac
done
if [ "$mode" = "drive" ]; then
  cmd=$(cat /dev/vdb)
elif [ -n "$mode" ]; then
  cmd=$(printf '%s' "$mode" | base64 -d)
fi
if [ -z "$cmd" ]; then
  echo "VF_POC_EXIT=127 missing vf.cmd"
  exit 127
fi
# Evidence is not bind-mounted. The command runs inside this rootfs.
sh -c "$cmd"
echo "VF_POC_EXIT=$?"
