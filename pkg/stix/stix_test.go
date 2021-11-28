package stix_test

import (
	"encoding/json"
	"os"
	"path"
	"testing"

	"github.com/shellcromancer/cti-go/pkg/stix"
)

func TestAttackPattern(t *testing.T) {
	name := path.Join("testdata", "attack-patterns.json")
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}

	var attackPatterns []stix.AttackPattern
	err = json.Unmarshal(data, &attackPatterns)
	if err != nil {
		t.Error(err)
	}

	t.Log(attackPatterns[0].Platforms)
}
