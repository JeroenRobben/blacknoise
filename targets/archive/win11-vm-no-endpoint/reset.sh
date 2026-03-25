#!/usr/bin/env bash

virsh -c qemu:///system snapshot-revert win11 win11-no-endpoint
sleep 5