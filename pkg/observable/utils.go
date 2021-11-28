package observable

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

func Refang(target string) (defanged string) {
	defanged = strings.Trim(target, "'`\"")
	defanged = strings.ReplaceAll(defanged, "[.]", ".")
	defanged = strings.ReplaceAll(defanged, "[:]", ":")
	defanged = strings.ReplaceAll(defanged, "(.)", ".")
	defanged = strings.ReplaceAll(defanged, "(:)", ":")
	if strings.HasPrefix(defanged, "hxxp") {
		defanged = "http" + strings.TrimPrefix(defanged, "hxxp")
	}
	if strings.HasPrefix(defanged, "hXXp") {
		defanged = "http" + strings.TrimPrefix(defanged, "hXXp")
	}

	return defanged
}

// Classify the observables type. It can be:
//  IP, domain, email, or hash (md5, sha1, sha256)
func Classify(observable string) Type {
	ip := net.ParseIP(observable)
	if ip != nil {
		return IP
	}

	uri, err := url.Parse(observable)
	if err == nil {
		if uri.Host != "" {
			return URL
		}
	}

	_, err = net.ParseMAC(observable)
	if err == nil {
		return MAC
	}

	emailRegex := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if emailRegex.MatchString(observable) {
		return Email
	}

	domainRegex := regexp.MustCompile(`(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]`)
	if domainRegex.MatchString(observable) {
		return Domain
	}

	if len(observable) == 32 {
		return MD5Hash
	}

	if len(observable) == 40 {
		return SHA1Hash
	}

	if len(observable) == 64 {
		return SHA256Hash
	}

	return ""
}
