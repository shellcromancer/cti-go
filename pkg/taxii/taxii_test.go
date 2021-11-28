package taxii_test

import (
	"testing"

	"github.com/shellcromancer/cti-go/pkg/taxii"
)

func TestTAXII_All(t *testing.T) {
	tests := []struct {
		name         string
		taxiiVersion string
		server       string
		username     string
		password     string
		// client       *taxii.Client
	}{
		{"Alienware TAXII 1.1", taxii.Version1_1, "https://otx.alienvault.com", "FIXME", "FIXME"},
		{"MITRE CTI TAXII 2.0", taxii.Version2_0, "https://cti-taxii.mitre.org", "", ""},
		{"Anomoli TAXII 2.0", taxii.Version2_0, "https://limo.anomali.com", "guest", "guest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []taxii.ClientOption{
				taxii.WithVersion(tt.taxiiVersion),
				taxii.WithServer(tt.server),
			}
			if tt.username != "" {
				opts = append(opts, taxii.WithBasicAuth(tt.username, tt.password))
			}

			tClient, err := taxii.NewClient(opts...)
			if err != nil {
				t.Fatal(err)
			}

			discovered, err := tClient.Discovery()
			if err != nil {
				t.Error(err)
			}

			t.Logf("Discovered %d API roots.", len(discovered.APIRoots))
			for i, root := range discovered.APIRoots {
				t.Logf("API Root %d: %s", i+1, root)

				collections, err := tClient.ListCollections(root)
				if err != nil {
					t.Fatal(err)
				}

				for _, collection := range collections {
					bundle, err := tClient.GetObjects(root, collection.ID)
					if err != nil {
						t.Error(err)
					}

					t.Logf("%s has %d objects", collection.Title, len(bundle.Objects))
				}
			}
		})
	}
}
