package service

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

// generateIPSecPSK generates a cryptographically random IPSec pre-shared key.
func generateIPSecPSK() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "fallback-psk-change-me"
	}
	return hex.EncodeToString(b)
}

func (s *L2TPService) initGlobalDaemons() {
	// 1. Setup IPsec (StrongSwan) Global Config
	ipsecConf := `config setup
    uniqueids=never
    charondebug="ike 1, knl 1, cfg 1"

conn %%default
    keyingtries=3
    ikelifetime=28800s
    lifetime=3600s
    dpddelay=15s
    dpdtimeout=45s
    dpdaction=clear
    ike=aes256-sha256-modp2048,aes128-sha256-modp2048,aes128-sha1-modp1024,aes128-md5-modp1024,3des-sha1-modp2048!
    esp=aes256-sha256,aes256-sha1,aes128-sha1,aes128-sha1-modp1024,3des-sha1!

conn L2TP-PSK
    authby=secret
    auto=add
    type=transport
    left=%s
    right=%%any
    rightprotoport=17/%%any
    leftprotoport=17/1701
`
	_ = os.WriteFile("/etc/ipsec.conf", []byte(fmt.Sprintf(ipsecConf, s.vpsPublicIP)), 0644)

	// Persist IPSec PSK
	pskPath := "/etc/ipsec.d/jinom-psk"
	var psk string

	if data, err := os.ReadFile(pskPath); err == nil {
		psk = strings.TrimSpace(string(data))
	}

	if psk == "" {
		psk = generateIPSecPSK()
		_ = os.MkdirAll("/etc/ipsec.d", 0755)
		if err := os.WriteFile(pskPath, []byte(psk), 0600); err != nil {
			s.log.Warn("Failed to persist IPSec PSK, using generated value in memory", zap.Error(err))
		}
	}

	ipsecSecrets := fmt.Sprintf(": PSK \"%s\"\n", psk)
	_ = os.WriteFile("/etc/ipsec.secrets", []byte(ipsecSecrets), 0600)

	s.log.Info("IPSec PSK initialized", zap.Int("length", len(psk)))

	// 2. Setup XL2TPD Global Config
	xl2tpdConf := `[global]
port = 1701
access control = no

[lns default]
exclusive = no
ip range = 10.255.255.100-10.255.255.250
local ip = 10.255.255.1
require chap = yes
refuse pap = yes
require authentication = yes
name = jinom-vpn
pppoptfile = /etc/ppp/options.xl2tpd
length bit = no
`
	_ = os.MkdirAll("/etc/xl2tpd", 0755)
	_ = os.WriteFile("/etc/xl2tpd/xl2tpd.conf", []byte(xl2tpdConf), 0644)

	// 3. Setup PPP Options
	pppOpts := `ipcp-accept-local
ipcp-accept-remote
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
noccp
novj
novjccomp
nobsdcomp
nodeflate
hide-password
debug
name jinom-vpn
proxyarp
lcp-echo-interval 15
lcp-echo-failure 4
mtu 1400
mru 1400
`
	_ = os.MkdirAll("/etc/ppp", 0755)
	_ = os.WriteFile("/etc/ppp/options.xl2tpd", []byte(pppOpts), 0644)

	// 4. Restart services gracefully
	_ = exec.Command("systemctl", "enable", "strongswan-starter").Run()
	_ = exec.Command("systemctl", "enable", "xl2tpd").Run()
	_ = exec.Command("systemctl", "restart", "strongswan-starter").Run()
	_ = exec.Command("systemctl", "restart", "xl2tpd").Run()
}

func (s *L2TPService) installIPUpScript() {
	scriptPath := "/etc/ppp/ip-up.d/99-jinom-routes"
	scriptContent := `#!/bin/sh
# Called by pppd when link comes up.
# PEERNAME contains the authenticated username (e.g., jinom-res-123)

exec >> /var/log/jinom-vpn-ppp.log 2>&1
echo "=== ip-up triggered at $(date) ==="
echo "Args: 1:$1 2:$2 3:$3 4:$4 5:$5 6:$6"
echo "Env PEERNAME: $PEERNAME"

if [ -n "$PEERNAME" ]; then
    NS_NAME=$(echo "$PEERNAME" | sed 's/jinom-/ns-/')
    echo "Derived namespace: $NS_NAME"
    
    if ip netns list | grep -q "^$NS_NAME"; then
        echo "Moving $1 to namespace $NS_NAME"
        ip link set "$1" netns "$NS_NAME"
        ip netns exec "$NS_NAME" ip link set "$1" up
        
        echo "Assigning IP $4 peer $5 inside namespace"
        ip netns exec "$NS_NAME" ip addr add $4 peer $5 dev "$1"
        ip netns exec "$NS_NAME" ip route add default dev "$1" || true
        
        # Idempotent NAT masquerade: check before add
        ip netns exec "$NS_NAME" iptables -t nat -C POSTROUTING -o "$1" -j MASQUERADE 2>/dev/null || \
            ip netns exec "$NS_NAME" iptables -t nat -A POSTROUTING -o "$1" -j MASQUERADE
        
        if [ -f "/etc/ppp/routes.$NS_NAME" ]; then
            while read subnet; do
                if [ -n "$subnet" ]; then
                    echo "Adding route to $subnet"
                    ip netns exec "$NS_NAME" ip route add "$subnet" dev "$1" || true
                fi
            done < "/etc/ppp/routes.$NS_NAME"
        fi
    else
        echo "Namespace $NS_NAME not found!"
    fi
fi
`
	_ = os.MkdirAll("/etc/ppp/ip-up.d", 0755)
	_ = os.WriteFile(scriptPath, []byte(scriptContent), 0755)
}
