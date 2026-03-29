package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func RandomBytes(maxLen int) ([]byte, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(maxLen+1)))
	if err != nil {
		return nil, err
	}
	n := int(nBig.Int64())
	buf := make([]byte, n)
	if _, err = rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func ValidatePoW(bits int, parts ...string) bool {
	if bits < 1 || bits > 256 {
		return false
	}
	data := strings.Join(parts, "")
	sum := sha256.Sum256([]byte(data))
	fullBytes := bits / 8
	for i := 0; i < fullBytes; i++ {
		if sum[i] != 0 {
			return false
		}
	}
	remBits := bits % 8
	if remBits > 0 {
		mask := byte(0xFF << (8 - remBits))
		if (sum[fullBytes] & mask) != 0 {
			return false
		}
	}
	return true
}

func IsTrustedProxy(list, ipStr string) bool {
	if list == "" || ipStr == "" {
		return false
	}
	ipStr = strings.TrimSpace(ipStr)
	if h, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = h
	}
	if strings.HasPrefix(ipStr, "[") && strings.HasSuffix(ipStr, "]") {
		ipStr = ipStr[1 : len(ipStr)-1]
	}
	if i := strings.LastIndex(ipStr, "%"); i != -1 { // fe80::1%eth0
		ipStr = ipStr[:i]
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	for _, raw := range strings.Split(list, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if entry == "*" {
			return true
		}
		// CIDR（IPv4/IPv6）
		if strings.Contains(entry, "/") {
			if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		// if "192.168.*.*"
		if strings.Contains(entry, "*") {
			if ip4 == nil {
				continue
			}
			pSegs := strings.Split(entry, ".")
			if len(pSegs) != 4 {
				continue
			}
			matched := true
			for i := 0; i < 4; i++ {
				if pSegs[i] == "*" {
					continue
				}
				n, err := strconv.Atoi(pSegs[i])
				if err != nil || n < 0 || n > 255 || int(ip4[i]) != n {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
			continue
		}
		if e := net.ParseIP(entry); e != nil && e.Equal(ip) {
			return true
		}
	}
	return false
}

// CheckAuthWithAccountMap
// u current login user
// p current login passwd
// user global user
// passwd global passwd
// accountMap enable multi user auth
func CheckAuthWithAccountMap(u, p, user, passwd string, accountMap, authMap map[string]string) bool {
	// Single account check
	noAccountMap := len(accountMap) == 0
	noAuthMap := len(authMap) == 0
	if noAccountMap && noAuthMap {
		return u == user && p == passwd
	}
	// Multi-account authentication check
	if len(u) == 0 {
		return false
	}
	if u == user && p == passwd {
		return true
	}
	if !noAccountMap {
		if P, ok := accountMap[u]; ok && p == P {
			return true
		}
	}
	if !noAuthMap {
		if P, ok := authMap[u]; ok && p == P {
			return true
		}
	}
	return false
}

// CheckAuth Check if the Request request is validated
func CheckAuth(r *http.Request, user, passwd string, accountMap, authMap map[string]string) bool {
	// Bypass authentication only if user, passwd are empty and multiAccount is nil or empty
	if user == "" && passwd == "" && len(accountMap) == 0 && len(authMap) == 0 {
		return true
	}
	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		s = strings.SplitN(r.Header.Get("Proxy-Authorization"), " ", 2)
		if len(s) != 2 {
			return false
		}
	}
	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return false
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return false
	}
	return CheckAuthWithAccountMap(pair[0], pair[1], user, passwd, accountMap, authMap)
}

func DealMultiUser(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	multiUserMap := make(map[string]string)
	for _, v := range strings.Split(s, "\n") {
		if strings.TrimSpace(v) == "" {
			continue
		}
		item := strings.SplitN(v, "=", 2)
		if len(item) == 0 {
			continue
		} else if len(item) == 1 {
			item = append(item, "")
		}
		multiUserMap[strings.TrimSpace(item[0])] = strings.TrimSpace(item[1])
	}
	return multiUserMap
}
