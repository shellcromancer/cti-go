package observable_test

import (
	"testing"

	"github.com/shellcromancer/cti-go/pkg/observable"
)

func TestRefangObersable(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"fanged", "https://malicious.link", "https://malicious.link"},
		{"defanged - square brackets", "https[:]//malicious[.]link", "https://malicious.link"},
		{"defanged - round brackets", "https(:)//malicious(.)link", "https://malicious.link"},
		{"defanged - hxxp", "hxxp://vulnerable.af", "http://vulnerable.af"},
		{"defanged - hXXp, square brackets", "hXXps://malicious[.]link", "https://malicious.link"},
		{"defanged - hXXp, round brackets", "hXXps://malicious(.)link", "https://malicious.link"},
		{"defanged - square brackets", "192[.]10[.]12[.]14", "192.10.12.14"},
		{"defanged - backtick escape (Google Chat)", "`1.1.1.1`", "1.1.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fanged := observable.Refang(tt.input)
			if fanged != tt.expected {
				t.Errorf("mismatched expectations. got=(%q) expected=(%q)", fanged,
					tt.expected)
			}
		})
	}
}

func TestClassifyObservable(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected observable.Type
	}{
		{"url", "https://malicious.link", observable.URL},
		{"ipv4", "1.1.1.1", observable.IP},
		{"ipv6", "2600:1700:b040:69e0:ccc9:3b51:68f2:502", observable.IP},
		{"domain", "malicious.link", observable.Domain},
		{"hash - md5", "098f6bcd4621d373cade4e832627b4f6", observable.MD5Hash},
		{"hash - sha1", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", observable.SHA1Hash},
		{"hash - sha2", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", observable.SHA256Hash},
		{"email", "user@domain.com", observable.Email},
		{"mac", "2C:54:91:88:C9:E3", observable.MAC},
		{"unknown", "foobar", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iocType := observable.Classify(tt.input)
			if iocType != tt.expected {
				t.Errorf("mismatched expectations. got=(%s) expected=(%q)", iocType,
					tt.expected)
			}
		})
	}
}
