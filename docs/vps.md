# Manual VPS route setup

Normal Lemonbox use needs no VPS SSH account, administrator key or remote installer. The existing route is already installed. This runbook is for an administrator preparing or repairing an exit VPS separately; it does not automate changes to the server.

## Before changing anything

Root or equivalent sudo access is required for WireGuard, forwarding, firewall and systemd changes. Confirm the server's OS, public address, real uplink interface, routes, current firewall backend/rules and listening services. Inspect existing Hysteria, SSH and VPN services. Do not assume another provider uses the same interface names or firewall policy.

Record the current configuration and rules. Keep independent console or recovery access available, with a bounded rollback plan. Avoid replacing the server's complete firewall or changing SSH while relying on that same connection for recovery.

On the server, use native read-only inspection first:

```sh
hostnamectl
ip -4 address
ip -4 route
sudo wg show
sudo nft list ruleset
sudo ss -lntup
systemctl --failed
```

Read the relevant systemd unit definitions and recent journals before restarting services. Keep WireGuard private keys out of reports. The expected service order is firewall/forwarding, WireGuard, framed loopback listener and the existing Hysteria service; inspect the real unit names instead of assuming names from another server. No public IP, subnet allocation or provider metadata should be inferred from a local interface prefix alone.

## Required route

The host gateway connects through the fixed Hysteria chain to the exit server's loopback framed listener. That listener carries encrypted WireGuard datagrams to the server's local WireGuard listener. Guest packets are then forwarded to the Internet with the configured public source.

The protocol constants are in [route_contract.py](../vm/route_contract.py): guest `10.77.0.2/30`, server WireGuard `10.78.0.1/30`, client `10.78.0.2/30`, MTU 1500, local WireGuard UDP 51820 and framed TCP 51822. The compatible transport implementation is [stream.py](../gateway/stream.py); its server role listens on loopback and uses the adjacent route contract. Keep both listeners private. Hysteria must be able to reach the framed loopback listener; public WireGuard/listener exposure is unnecessary.

Configure a server WireGuard key and the intended client public key. The peer's allowed source addresses must cover the client `10.78.0.2` and canonical guest `10.77.0.2`. Save the matching client private key and server public key in the host's private shared route settings. Never place private transport keys in the checkout or guest. One host gateway serves multiple simultaneous VM profiles: it validates their distinct TAP/source pairs before translating them to the canonical guest address. New local VM profiles do not require server peer changes. Do not start another independent host gateway with the same client key.

Enable IPv4 forwarding and integrate narrowly scoped rules with the existing policy. Permit the intended guest's public destinations through the WireGuard interface and actual uplink; deny private/LAN/metadata and IPv6 forwarding. Apply explicit SNAT to the configured public exit. Add a guard after source NAT that drops forwarded route traffic with any other source or uplink, including established traffic. This order matters: an early established-connection accept must not bypass the final source guard.

Use native services for the WireGuard interface, framed listener and firewall. Keep the guard active during transport outages. Changing these affects this guest's connectivity; a wholesale firewall replacement can also break unrelated services.

## Verify and recover

Check both endpoint keys, peer allowed addresses, loopback listener bindings, actual routes, MTU, SNAT and guard counters. Verify TCP, DNS, UDP/STUN and ICMP from the guest use the exact public exit. A sampled IP check complements the source guard; it does not replace it. Check that transport loss closes guest Internet access while guest management SSH remains available.

The host gateway continuously verifies the route and automatically retries transient failures on the same route while guest traffic stays closed. It publishes recovery state and alerts; `lemonbox status` and other local Lemonbox commands display those reports when invoked. If an alert identifies a cause requiring administrator repair, restore the underlying service first. For manual gateway replacement, run `lemonbox stop --all`, choose **Recover shared gateway** in `lemonbox settings`, then start the VMs you need. Incorrect keys or server policy require separate administrator repair; Lemonbox never signs in to the VPS. Restore recorded service/firewall state through independent recovery access when needed, and verify the exit and guard again before resuming work.
