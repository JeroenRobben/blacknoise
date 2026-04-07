#!/usr/bin/env bash
set -e

virsh -c qemu:///system snapshot-revert netbsd10.1 netbsd10.1-hardcoded-endpoint
sleep 5
