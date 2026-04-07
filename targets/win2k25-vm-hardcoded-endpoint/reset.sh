#!/usr/bin/env bash
set -e

virsh -c qemu:///system snapshot-revert win2k25 win2k25-hardcoded-endpoint
sleep 5