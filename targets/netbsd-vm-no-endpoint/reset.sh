#!/usr/bin/env bash
set -e

virsh -c qemu:///system snapshot-revert netbsd10.1 netbsd-no-endpoint
sleep 5
