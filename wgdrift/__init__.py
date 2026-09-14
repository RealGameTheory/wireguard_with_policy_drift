"""wgdrift: continuous policy-drift control loop for WireGuard gateways.

Stage layout (see docs/architecture.md):
  1. collect     - read live kernel state: WireGuard, routing, nftables
  2. reachability - compute effective reachability from that state
  3. policy      - load the declarative YAML policy
  4. drift       - diff effective state against policy
  5. reconcile   - safely converge the gateway, never locking out admins



"""

__version__ = "0.1.0"
