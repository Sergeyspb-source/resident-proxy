#!/usr/bin/env bash
set -euo pipefail

runtime=/run/exitnode-route
owned=$runtime/network-owned
tun=exitnode-r2
dns_link=exnode-dns
dns_peer=exnode-peer
dns_netns=exnode-dns-route
dns_host=172.31.252.1
dns_server=172.31.252.2
fake4=198.19.255.248/29
fake6=fd00:198:19::/112
table=29444
nft_table=exitnode_route
socks_port=108

config() {
    local domain=${EXITNODE_ROUTE_DOMAIN:?}
    if [[ ${#domain} -gt 253 || ! $domain =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
        echo 'EXITNODE_ROUTE_DOMAIN must be a lowercase ASCII hostname' >&2
        return 1
    fi
    cat <<EOF
{
  "log": {"level": "info", "timestamp": true},
  "experimental": {"cache_file": {"enabled": true, "path": "$runtime/fakeip.db", "store_fakeip": true}},
  "dns": {
    "servers": [
      {"type": "udp", "tag": "host-dns", "server": "127.0.0.53"},
      {"type": "fakeip", "tag": "windows-dns", "inet4_range": "$fake4", "inet6_range": "$fake6"}
    ],
    "rules": [
      {"domain": ["$domain"], "query_type": ["A", "AAAA"], "action": "route", "server": "windows-dns", "rewrite_ttl": 3},
      {"domain": ["$domain"], "action": "predefined", "rcode": "NOERROR"},
      {"action": "predefined", "rcode": "REFUSED"}
    ],
    "final": "host-dns"
  },
  "inbounds": [
    {"type": "direct", "tag": "split-dns", "netns": "$dns_netns", "listen": "$dns_server", "listen_port": 53},
    {
      "type": "tun", "tag": "selected-site", "interface_name": "$tun",
      "address": ["172.31.253.1/30"], "auto_route": false, "dns_mode": "disabled", "stack": "gvisor"
    }
  ],
  "outbounds": [{
    "type": "socks", "tag": "owner-node", "server": "127.0.0.1",
    "server_port": $socks_port, "version": "5", "network": "tcp"
  }],
  "route": {
    "default_domain_resolver": "host-dns",
    "rules": [
      {"inbound": "split-dns", "action": "hijack-dns"},
      {
        "inbound": "selected-site", "domain": ["$domain"], "port": 443, "network": "tcp",
        "action": "route", "outbound": "owner-node"
      },
      {"action": "reject"}
    ],
    "final": "owner-node"
  }
}
EOF
}

# GPT: Set up the DNS link and refusal rules before the engine is allowed to start.
start_network() {
    [[ $EUID -eq 0 && -d $runtime && ! -e $owned ]]
    exec 9>/etc/exitnode-route/.profile.lock
    flock -x -w 12 9
    local key value
    while IFS='=' read -r key value; do
        if [[ $key == EXITNODE_ROUTE_DOMAIN ]]; then
            EXITNODE_ROUTE_DOMAIN=$value
        fi
    done < /etc/exitnode-route/route.env
    if ip link show dev "$dns_link" >/dev/null 2>&1 ||
       ip link show dev "$dns_peer" >/dev/null 2>&1 ||
       ip link show dev "$tun" >/dev/null 2>&1 ||
       [[ -e /run/netns/$dns_netns ]] ||
       ip -4 rule show | grep -E '^(91|92|93):' ||
       ip -6 rule show | grep -E '^93:' ||
       [[ -n $(ip -4 route show table "$table" 2>/dev/null || true) ]] ||
       [[ -n $(ss -ltnH "sport = :$socks_port") ]] ||
       nft list table inet "$nft_table" >/dev/null 2>&1; then
        echo 'An existing link, route rule, table, or SOCKS listener overlaps exitnode-route' >&2
        return 1
    fi
    if resolvectl domain | awk -v domain="$EXITNODE_ROUTE_DOMAIN" '
        { for (i=1; i<=NF; i++) if ($i==domain || $i=="~" domain) found=1 }
        END { exit !found }
    '; then
        echo 'Another DNS link already serves the same routing domain' >&2
        return 1
    fi
    if (( $(sysctl -n net.ipv4.ip_unprivileged_port_start) <= socks_port )); then
        echo 'SOCKS port is not reserved for privileged binding on this machine' >&2
        return 1
    fi
    config > "$runtime/engine.json"
    /usr/local/lib/exitnode-route/sing-box check -c "$runtime/engine.json"
    (set -o noclobber; : > "$owned")

    nft -f - <<EOF
table inet $nft_table {
    chain local_output {
        type filter hook output priority -10; policy accept;
        ip daddr 127.0.0.1 tcp dport $socks_port meta skuid != 0 reject with tcp reset
    }
}
EOF
    ip -4 rule add unreachable pref 93 to "$fake4"
    ip -6 rule add unreachable pref 93 to "$fake6"
    ip -4 rule add pref 92 to "$fake4" lookup "$table"
    ip netns add "$dns_netns"
    ip link add "$dns_link" type veth peer name "$dns_peer" netns "$dns_netns"
    ip addr add "$dns_host/30" dev "$dns_link"
    ip link set "$dns_link" up
    ip -n "$dns_netns" addr add "$dns_server/30" dev "$dns_peer"
    ip -n "$dns_netns" link set "$dns_peer" up
    ip -4 route add table "$table" "$dns_server/32" dev "$dns_link" src "$dns_host"
    ip -4 rule add pref 91 to "$dns_server/32" lookup "$table"
    resolvectl default-route "$dns_link" no
    resolvectl dnssec "$dns_link" no
    resolvectl dnsovertls "$dns_link" no
    resolvectl dns "$dns_link" "$dns_server"
    resolvectl domain "$dns_link" "~$EXITNODE_ROUTE_DOMAIN"
    printf 'DNS policy active for %s via configured owner %s\n' "$EXITNODE_ROUTE_DOMAIN" "$EXITNODE_ROUTE_OWNER"
}

# GPT: Restore the TUN route only after both listeners have come up.
attach_engine() {
    [[ $EUID -eq 0 && -f $owned ]]
    for ((attempt=0; attempt<25; attempt++)); do
        if ip link show dev "$tun" >/dev/null 2>&1 &&
           ip netns exec "$dns_netns" ss -lunH sport = :53 | grep -F "$dns_server:53" >/dev/null; then
            ip -4 route replace table "$table" "$fake4" dev "$tun"
            return
        fi
        sleep .2
    done
    echo 'The TUN or dedicated DNS listener did not become ready' >&2
    return 1
}

# GPT: Deactivate the dedicated resolver and delete only this service's network state.
stop_network() {
    [[ $EUID -eq 0 ]]
    [[ -f $owned ]] || return 0
    if ip link show dev "$dns_link" >/dev/null 2>&1; then
        resolvectl revert "$dns_link" 2>/dev/null || true
        ip link del dev "$dns_link"
    fi
    if [[ -e /run/netns/$dns_netns ]]; then
        ip netns del "$dns_netns"
    fi
    ip -4 rule del pref 91 to "$dns_server/32" lookup "$table" 2>/dev/null || true
    ip -4 rule del pref 92 to "$fake4" lookup "$table" 2>/dev/null || true
    ip -4 route del table "$table" "$fake4" dev "$tun" 2>/dev/null || true
    ip -4 rule del unreachable pref 93 to "$fake4" 2>/dev/null || true
    ip -6 rule del unreachable pref 93 to "$fake6" 2>/dev/null || true
    nft delete table inet "$nft_table" 2>/dev/null || true
    rm -f -- "$owned"
    echo 'DNS and policy routes deactivated'
}

case "${1:-}" in
    config) config ;;
    start) start_network ;;
    attach) attach_engine ;;
    stop) stop_network ;;
    *) printf 'Usage: %s config|start|attach|stop\n' "$0" >&2; exit 2 ;;
esac
