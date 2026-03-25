#!/usr/bin/env bash

virsh -c qemu:///system snapshot-revert ubuntu25.10 ubuntu-client-hardcoded-endpoint
sleep 5