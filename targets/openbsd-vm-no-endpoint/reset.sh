#!/usr/bin/env bash
set -e

virsh -c qemu:///system snapshot-revert openbsd7.8 openbsd7.8-no-endpoint
sleep 5
