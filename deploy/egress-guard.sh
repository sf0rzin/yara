#!/usr/bin/env bash
#
# Keeps the sync container from reaching anything that is not the public
# internet.
#
# The icon proxy fetches favicons on behalf of an unauthenticated caller, which
# makes it an SSRF vector by construction. The domain is validated in the
# service — it becomes both a URL to fetch and a filename to write, so a slash
# or a dot-dot would be a path traversal and a scheme or a port would aim the
# fetch elsewhere — but string validation cannot catch `10-3-0-11.nip.io`, and
# an application-level resolve-then-connect check is racy against DNS rebinding
# by construction. A packet filter is neither.
#
# On the machine this service was designed for, that filter was systemd's
# IPAddressDeny. In a container there is no such directive, so the equivalent
# is written here against the pinned subnet from docker-compose.yml.
#
# Two hooks, because a container can reach private space two different ways:
#
#   DOCKER-USER  traffic forwarded onward — other containers, the private
#                network, anything routed
#   INPUT        traffic to this host's own addresses, which is delivered
#                locally and therefore never reaches the FORWARD chain. This
#                is the one that is easy to miss: without it the container can
#                still open sshd on the host's public address.
#
# Idempotent, and safe to run again after `docker compose up` — Docker rebuilds
# its own chains when networks are recreated, which can drop the hooks.
#
#   sudo install -m 0755 egress-guard.sh /usr/local/bin/yara-egress-guard
#   sudo yara-egress-guard

set -euo pipefail

# Must match the `app` network in docker-compose.yml. The two are pinned to
# each other on purpose: a Docker-allocated subnet would make this filter
# quietly protect the wrong range.
readonly APP_SUBNET="172.28.1.0/24"

readonly CHAIN="YARA-EGRESS"
readonly HOST_CHAIN="YARA-NOHOST"

# Everything that is not the public internet. Deliberately not a matching
# allow-list: an allow entry is an exception that has to be re-justified every
# time the deny list grows, and this list only ever grows.
readonly PRIVATE=(
	10.0.0.0/8
	172.16.0.0/12
	192.168.0.0/16
	169.254.0.0/16
	100.64.0.0/10
	192.0.0.0/24
	198.18.0.0/15
)

if [[ $EUID -ne 0 ]]; then
	echo "must run as root" >&2
	exit 1
fi

# Create or empty. Flushing rather than deleting keeps the hooks in DOCKER-USER
# and INPUT valid while the rules are rewritten, so there is no window in which
# the chain exists and permits everything.
ensure_chain() {
	iptables -nL "$1" >/dev/null 2>&1 || iptables -N "$1"
	iptables -F "$1"
}

ensure_chain "$CHAIN"
ensure_chain "$HOST_CHAIN"

# Caddy talks to sync across this subnet, so intra-network traffic returns
# before the deny list is consulted. This has to come first: the subnet lives
# inside 172.16.0.0/12 and would otherwise be dropped by the rule meant for
# everything else.
iptables -A "$CHAIN" -d "$APP_SUBNET" -j RETURN

for net in "${PRIVATE[@]}"; do
	iptables -A "$CHAIN" -d "$net" -j DROP
done

# Fall through to whatever Docker would have done. The chain is a filter on the
# way past, not a verdict on everything.
iptables -A "$CHAIN" -j RETURN

# The host itself, on any of its addresses. Nothing in this project has a
# reason to reach it, and the host is listening on 22 and 3999.
iptables -A "$HOST_CHAIN" -j DROP

hook() {
	local parent="$1" target="$2"
	iptables -C "$parent" -s "$APP_SUBNET" -j "$target" 2>/dev/null ||
		iptables -I "$parent" 1 -s "$APP_SUBNET" -j "$target"
}

hook DOCKER-USER "$CHAIN"
hook INPUT "$HOST_CHAIN"

echo "egress guard applied to $APP_SUBNET"
