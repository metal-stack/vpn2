# Wireguard POC

This document outlines the POC for replacing OpenVPN with WireGuard. It details the motivation, implementation approach, and deployment steps for evaluating WireGuard as an alternative VPN solution.

## Motivation
The current OpenVPN implementation establishes a TCP connection through the istio-ingress gateway, functioning as an HTTP proxy. This setup results in slow connection establishment times, necessitating a high-availability (HA) configuration to minimize downtime. By transitioning to WireGuard, we anticipate significantly faster connection establishment, reducing the need for complex HA mechanisms and improving overall reliability.


As we use a TCP connection with WireGuard, we have TCP over TCP with the following drawbacks:

- **Performance degradation:** TCP over TCP can lead to inefficient retransmission and congestion control, causing increased latency and reduced throughput.
- **Head-of-line blocking:** Packet loss on the outer TCP connection can block delivery of all subsequent packets, even if the inner TCP stream would not require retransmission.
- **Inefficient error recovery:** Both layers may independently attempt to recover from packet loss, resulting in redundant retransmissions and increased overhead.
- **Poor handling of network changes:** TCP connections are sensitive to changes in network conditions, and tunneling TCP within TCP can amplify issues like connection resets or timeouts.
- **Suboptimal flow control:** The flow control mechanisms of both TCP layers can interfere with each other, leading to buffer bloat or underutilization of available bandwidth.

Although OpenVPN typically uses UDP by default, we were unable to identify a method to provide a single access point for all shoots using this protocol. In contrast, the WireGuard protocol enables dispatching connections based on the public key, allowing for a unified access point that can route traffic to the appropriate shoot.

## Concept

This POC leverages the [wireguard-go](https://github.com/WireGuard/wireguard-go) implementation for WireGuard functionality. Secrets required for WireGuard are managed using the Gardener secrets manager.

Since Istio cannot natively route UDP packets, we utilize [Multiple WireGuard Proxy (MWGP)](https://github.com/apernet/mwgp) to forward UDP traffic to the appropriate `vpn-seed-server`. MWGP operates by inspecting the WireGuard handshake: it requires the private keys of the `vpn-seed-server` and the public keys of the `vpn-shoot-client` to decrypt the handshake and determine the correct shoot cluster based on the public key. This enables MWGP to dispatch incoming connections to the correct backend.

Currently, this POC demonstrates the setup for a single shoot cluster. To support multiple shoots, the secrets (private and public keys) from all shoots must be aggregated into a unified MWGP configuration, allowing MWGP to route connections for any shoot based on the presented public key.


## Deploy

The POC works both in the local setup and in the extensions setup. However, to really test the VPN connection the extension setup is required.

* Build the docker images:
```
make wireguard-vpn-client-docker-image
make wirefuard-vpn-server-docker-image
```

Push the images to a registry and update the images in [gardener/gardener](https://github.com/gardener/gardener/blob/master/imagevector/containers.yaml)

* Start the extensions setup with the [g/g branch](https://github.com/axel7born/gardener/tree/wireguard) containing the necessary changes. Istio-ingress needs an addtion [secret](https://github.com/axel7born/gardener/blob/c1aba04527d0814a50f09856d1b996dbb4e53b76/pkg/component/networking/istio/charts/istio/istio-ingress/templates/deployment.yaml#L251-L259). This needs be to un-commented to get the istio-ingress pod come up.
* Deploy a shoot.
* Deploy network policies to allow all traffic to istio-ingress and shoot namespace:
```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
spec:
  podSelector: {}
  ingress:
  - {}
  egress:
  - {}
  policyTypes:
  - Ingress
  - Egress
```
TODO. Check why this is needed, as network policies for the new port are automatically created.

* Comment the [secret](https://github.com/axel7born/gardener/blob/c1aba04527d0814a50f09856d1b996dbb4e53b76/pkg/component/networking/istio/charts/istio/istio-ingress/templates/deployment.yaml#L251-L259) in the istio-ingress deployment and `make gardener-extensions-up`, so that the secrete containing the shoot credentials will not be overwritten.

## Next Steps
* Test network connection: resiliance, downtime during new deployment, throuput..
* Aggregate the secrets from all shoots to generate a unified MWGP configuration.
* Currently MWPG needs to be restarted to get the new configuration. Whis would have to be done for each new shoot. Check if this is a problem and if it can be avoided.
* Check if the functionality of MWGP can be implemented as Istio plugin.
* Refactor and finalize the implementation to prepare PRs.

## FIPS
* Wireguard is not fips complient. [WolfSSL](https://github.com/wolfSSL/osp/blob/master/wireguard-go/README.md) might be an option.

