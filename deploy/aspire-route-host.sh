#!/usr/bin/env bash
set -euo pipefail

domain=speed.cloudflare.com
ip4=198.19.255.254
ip6=fd00:198:19::fe
iface=exitnode-r1
table=29443
route_priority=92
guard_priority=93
marker='# exitnode-aspire-host-pilot'
workdir=$(dirname -- "$(readlink -f -- "$0")")
lease=$workdir/lease

render_config() {
    cat <<EOF
{
  "log": {"level": "info", "timestamp": true},
  "dns": {
    "servers": [{"type": "udp", "tag": "host-dns", "server": "127.0.0.53"}],
    "final": "host-dns"
  },
  "inbounds": [{
    "type": "tun", "tag": "selected-site", "interface_name": "$iface",
    "address": ["172.31.253.1/30"], "auto_route": false,
    "dns_mode": "disabled", "stack": "gvisor"
  }],
  "outbounds": [{
    "type": "socks", "tag": "windows-pc",
    "server": "127.0.0.1", "server_port": 19080, "version": "5", "network": "tcp"
  }],
  "route": {
    "default_domain_resolver": "host-dns",
    "rules": [
      {
        "ip_cidr": ["$ip4/32"], "port": 443, "network": "tcp",
        "action": "route", "outbound": "windows-pc", "override_address": "$domain"
      },
      {"action": "reject"}
    ],
    "final": "windows-pc"
  }
}
EOF
}

# GPT: Put the guard in place before publishing the test addresses.
hold_route() {
    [[ $EUID -eq 0 && -d $workdir && ! -e $lease ]]
    [[ -f /etc/hosts && ! -L /etc/hosts && $(tail -c 1 /etc/hosts | od -An -tx1 | tr -d ' ') == 0a ]]
    if grep -Fq "$marker" /etc/hosts ||
       awk -v domain="$domain" -v a="$ip4" -v aaaa="$ip6" '
           { sub(/#.*/, ""); for (i=1; i<=NF; i++) if (tolower($i)==domain || $i==a || $i==aaaa) seen=1 }
           END { exit !seen }
       ' /etc/hosts ||
       ip -4 rule show | grep -E "^($route_priority|$guard_priority):" ||
       ip -6 rule show | grep -E "^$guard_priority:" ||
       [[ -n $(ip -4 route show table "$table" 2>/dev/null || true) ]]; then
        echo "An existing hosts entry, route table, or rule overlaps the pilot" >&2
        return 1
    fi
    ip link show dev "$iface" >/dev/null
    (set -o noclobber; : >"$lease")

    ip -4 rule add unreachable pref "$guard_priority" to "$ip4/32"
    ip -6 rule add unreachable pref "$guard_priority" to "$ip6/128"
    ip -4 route add table "$table" "$ip4/32" dev "$iface"
    ip -4 rule add pref "$route_priority" to "$ip4/32" lookup "$table"
    printf '%s %s %s\n%s %s %s\n' "$ip4" "$domain" "$marker" "$ip6" "$domain" "$marker" >> /etc/hosts
    echo "Host route active for $domain"
    exec sleep infinity
}

# GPT: Remove only the pilot records and leave other host settings intact.
rollback() {
    [[ $EUID -eq 0 ]]
    [[ -f $lease ]] || return 0
    sed -i '/^198[.]19[.]255[.]254 speed[.]cloudflare[.]com # exitnode-aspire-host-pilot$/d;
            /^fd00:198:19::fe speed[.]cloudflare[.]com # exitnode-aspire-host-pilot$/d' /etc/hosts
    ip -4 rule del pref "$route_priority" to "$ip4/32" lookup "$table" 2>/dev/null || true
    ip -4 route del table "$table" "$ip4/32" dev "$iface" 2>/dev/null || true
    ip -4 rule del unreachable pref "$guard_priority" to "$ip4/32" 2>/dev/null || true
    ip -6 rule del unreachable pref "$guard_priority" to "$ip6/128" 2>/dev/null || true
    rm -f -- "$lease"
    echo "Host route rolled back"
}

case "${1:-}" in
    config) render_config ;;
    hold) hold_route ;;
    rollback) rollback ;;
    *) printf 'Usage: %s config|hold|rollback\n' "$0" >&2; exit 2 ;;
esac
