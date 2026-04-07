#!/usr/bin/env bash
set -e

virsh -c qemu:///system snapshot-revert freebsd15.0 freebsd15.0-no-endpoint
sleep 5
