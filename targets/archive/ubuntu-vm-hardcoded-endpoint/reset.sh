#!/usr/bin/env bash
set -e

virsh -c qemu:///system snapshot-revert ubuntu25.10 ubuntu-client-hardcoded-endpoint
sleep 5