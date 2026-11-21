#!/usr/bin/env bash
set -euo pipefail

domain=speed.cloudflare.com
tun=exitnode-r2
dns_link=exnode-dns
dns_peer=exnode-peer
dns_netns=exnode-dns-test
dns_host=172.31.252.1
dns_server=172.31.252.2
fake4=198.19.255.248/29
fake6=fd00:198:19::/112
table=29444
workdir=$(dirname -- "$(readlink -f -- "$0")")
lease=$workdir/lease

render_config() {
    cat <<EOF
{
  "log": {"level": "info", "timestamp": true},
  "experimental": {"cache_file": {"enabled": true, "path": "fakeip.db", "store_fakeip": true}},
  "dns": {
    "servers": [
      {"type": "udp", "tag": "host-dns", "server": "127.0.0.53"},
      {"type": "fakeip", "tag": "windows-dns", "inet4_range": "$fake4", "inet6_range": "$fake6"}
    ],
    "rules": [
      {
        "domain": ["$domain"], "query_type": ["A", "AAAA"],
        "action": "route", "server": "windows-dns", "rewrite_ttl": 3
      },
      {"domain": ["$domain"], "action": "predefined", "rcode": "NOERROR"},
      {"action": "predefined", "rcode": "REFUSED"}
    ],
    "final": "host-dns"
  },
  "inbounds": [
    {
      "type": "direct", "tag": "split-dns", "netns": "$dns_netns",
      "listen": "$dns_server", "listen_port": 53
    },
    {
      "type": "tun", "tag": "selected-site", "interface_name": "$tun",
      "address": ["172.31.253.1/30"], "auto_route": false,
      "dns_mode": "disabled", "stack": "gvisor"
    }
  ],
  "outbounds": [{
    "type": "socks", "tag": "windows-pc",
    "server": "127.0.0.1", "server_port": 19080, "version": "5", "network": "tcp"
  }],
  "route": {
    "default_domain_resolver": "host-dns",
    "rules": [
      {"inbound": "split-dns", "action": "hijack-dns"},
      {
        "inbound": "selected-site", "domain": ["$domain"], "port": 443, "network": "tcp",
        "action": "route", "outbound": "windows-pc"
      },
      {"action": "reject"}
    ],
    "final": "windows-pc"
  }
}
EOF
}

# GPT: Hold split DNS and the fallback guard independently of the TUN process.
hold_network() {
    [[ $EUID -eq 0 && ! -e $lease ]]
    if ip link show dev "$dns_link" >/dev/null 2>&1 ||
       ip link show dev "$dns_peer" >/dev/null 2>&1 ||
       ip link show dev "$tun" >/dev/null 2>&1 ||
       [[ -e /run/netns/$dns_netns ]] ||
       ip -4 rule show | grep -E '^(91|92|93):' ||
       ip -6 rule show | grep -E '^93:' ||
       [[ -n $(ip -4 route show table "$table" 2>/dev/null || true) ]]; then
        echo "An existing link, namespace, route table, or rule overlaps the pilot" >&2
        return 1
    fi
    (set -o noclobber; : >"$lease")

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
    printf 'Split DNS link ready\n'
    exec sleep infinity
}

# GPT: Publish the domain only after the TUN and the dedicated DNS socket exist.
publish_domain() {
    [[ $EUID -eq 0 && -f $lease ]]
    ip link show dev "$tun" >/dev/null
    ip netns exec "$dns_netns" ss -lunH sport = :53 | grep -F "$dns_server:53"
    ip -4 route replace table "$table" "$fake4" dev "$tun"
    resolvectl default-route "$dns_link" no
    resolvectl dnssec "$dns_link" no
    resolvectl dnsovertls "$dns_link" no
    resolvectl dns "$dns_link" "$dns_server"
    resolvectl domain "$dns_link" "~$domain"
}

# GPT: Revert only the link and policy rules created by this pilot.
rollback() {
    [[ $EUID -eq 0 ]]
    [[ -f $lease ]] || return 0
    resolvectl revert "$dns_link" 2>/dev/null || true
    if ip link show dev "$dns_link" >/dev/null 2>&1; then
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
    rm -f -- "$lease"
    printf 'Split DNS pilot rolled back\n'
}

case "${1:-}" in
    config) render_config ;;
    hold) hold_network ;;
    publish) publish_domain ;;
    rollback) rollback ;;
    *) printf 'Usage: %s config|hold|publish|rollback\n' "$0" >&2; exit 2 ;;
esac
