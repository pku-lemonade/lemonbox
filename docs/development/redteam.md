# Detection limits

This guest is a real Debian virtual machine with its own kernel, systemd, normal user home, native SSH/Docker/Claude and ordinary private networking. That resembles many cloud servers, but it does not make the machine or location undetectable.

Guest root can identify KVM/QEMU through CPUID, firmware and virtio devices. NoCloud provisioning and an optional 9p host share are also observable. `/home/<username>` is normal for Debian; hostname is an administrator choice. Provider metadata should not be invented. A VPS can use a private interface and external NAT, so a private guest address alone is not an anomaly.

The network preserves guest TCP/UDP/ICMP behavior and uses the owned VPS's public exit, but latency, routing/MTU behavior and traffic timing can still suggest a tunnel. A service provider can observe the public IP's ASN/reputation, connection behavior and authenticated account history. Two machines sharing an exit does not uniquely establish proxy use.

Guest sudo cannot edit the host gateway or VPS enforcement; host/VPS administration can. Nested tunnels carried through permitted public destinations are not prohibited by this design. The guarantee is the controlled first hop and exit boundary, subject to the trusted host/VPS and their kernel rules—not that arbitrary software cannot infer virtualization, nor that an account will be accepted.

Browser fingerprint scanner scores measure selected browser properties and do not establish machine/location invisibility. Experimental scanner/alternate-carrier tooling has been removed from the supported product. Normal logs remain normal logs; operator reports and transient validation programs stay outside the guest filesystem.
