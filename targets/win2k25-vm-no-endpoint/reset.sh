#!/usr/bin/env bash
set -e

virsh -c qemu:///system snapshot-revert win2k25 win2k25-no-endpoint
sleep 5