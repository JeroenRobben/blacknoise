# blacknoise

> **Work in progress.**

A framework for security testing of [WireGuard](https://www.wireguard.com/papers/wireguard.pdf) implementations.
Testing is black-box: the framework behaves as a WireGuard peer and bugs are detected solely from the packets sent back by the implementation under test, or the absence thereof.

---

## Running tests

```bash
# Install dependencies
uv sync

# Run tests against a target
sudo python run_tests.py wireguard-go
```

The framework itself does not require special privileges, but `reset.sh` often does — for example to configure network interfaces or manage containers. Running with `sudo` ensures `reset.sh` has the necessary permissions.

---

## Target setup

The configuration for each WireGuard implementation under test lives in `targets/<name>/` and contains:

| File | Purpose |
|------|---------|
| `target.py` | `TestTarget` instance describing the test setup configuration |
| `reset.sh` | Script executed before each test run to reset the target to a clean state |
| `teardown.sh` | _(optional)_ Script executed after all tests complete, e.g. to stop a Docker container |


### Network

The test host requires **two IP addresses** (`server_physical_ip_1` and `server_physical_ip_2`) that can both reach the target at `target_physical_ip:target_wg_port`. The two host addresses are used to simulate endpoint changes in the roaming tests.

The target must run WireGuard with a single configured peer, using the configuration defined in `target.py`.

### Echo service

The target must run a UDP echo service that:

- Listens on **all interfaces** (physical and WireGuard) on `echo_port`
- Echoes every received UDP packet back to `server_wg_ip:echo_port` **through the WireGuard tunnel**

The echo service always replies via the tunnel regardless of which interface the probe arrived on. When the test host sends a probe to `target_physical_ip:echo_port` on the physical interface and no tunnel session exists yet, the target must establish a handshake in order to deliver the reply — this is the mechanism used to trigger the target to act as the WireGuard initiator.

Ready-to-use implementations are in `targets/shared/` (`udp_echo.c` for Linux/BSD, `udp_echo.ps1` for Windows).

## Adding a new target

1. Create `targets/<name>/` and copy an existing `target.py` as a starting point.
2. Fill in `target.py` with the network addresses, ports, and key pairs for the target.
3. Write `reset.sh` — it must reset the existing WireGuard configuration, ensure the echo service is running, and exit 0 on success. Two common approaches:
   - **VM snapshots**: take a snapshot after applying the WireGuard configuration from `target.py` and starting the echo service, then have `reset.sh` restore that snapshot.
   - **Docker**: run the target in a container and have `reset.sh` restart it. See the existing Docker targets in `targets/` for examples.
4. Optionally write `teardown.sh` — called once after all tests finish. Set `teardown_script` in `target.py` to point to it. Useful for stopping containers or other cleanup that should happen at the end.
5. Run the tests: `sudo python run_tests.py <name>`.

---


## Architecture

### Key modules

| Module | Purpose                                                                                                                                                                                |
|--------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `primitives.py` | Low-level operations and cryptographic primitives as defined in the [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf), using the same naming as in the whitepaper |
| `state_machine.py` | WireGuard state machine and packet handling for a single _secure session_                                                                                                              |
| `AbstractTest.py` | Base class for test cases; provides helpers for sending/receiving handshake and transport packets                                                                                      |
| `TestTarget.py` | Dataclass describing the target and test host configuration                                                                                                                            |
| `TestRunner.py` | Runs the test suite: calls `reset.sh` before each test, executes all tests, collects results, calls `teardown.sh` at the end                                                          |
| `test_cases/` | Individual test case implementations                                                                                                                                                   |
