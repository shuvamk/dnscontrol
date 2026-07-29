package linode

import (
	"testing"

	"github.com/DNSControl/dnscontrol/v5/models"
	"github.com/DNSControl/dnscontrol/v5/pkg/diff2"
	"github.com/DNSControl/dnscontrol/v5/pkg/nameservers"
)

func TestFixTTL(t *testing.T) {
	for i, test := range []struct {
		given, expected uint32
	}{
		{0, 0},
		{1, 300},
		{299, 300},
		{300, 300},
		{301, 3600},
		{2419202, 2419200},
		{600, 3600},
		{3600, 3600},
	} {
		found := fixTTL(test.given)
		if found != test.expected {
			t.Errorf("Test %d: Expected %d, but was %d", i, test.expected, found)
		}
	}
}

// mkRec is a test helper that builds a RecordConfig via the DomainConfig.
func mkRec(t *testing.T, dc *models.DomainConfig, label string, ttl uint32, typ, target string) *models.RecordConfig {
	t.Helper()
	rc, err := dc.NewRecordConfig(label, ttl, typ, target)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

// TestIgnoreApexNoSpuriousChanges reproduces integration test "IGNORE apex /
// apex label". Linode injects read-only apex NS records into the "existing"
// set. IGNORE("@") copies those existing apex records into "desired", so if the
// injected placeholders don't match the desired apex NS records (added by
// AddNSRecords) the diff engine reports spurious changes. See appendDefaultNS.
func TestIgnoreApexNoSpuriousChanges(t *testing.T) {
	dc, err := models.NewDomainConfig("dnscontroltest-linode.com")
	if err != nil {
		t.Fatal(err)
	}

	// Desired config: the "apex label" test case keeps only the non-apex
	// records plus IGNORE("@") with the safety check disabled.
	dc.Records = models.Records{
		mkRec(t, dc, "bar", 300, "A", "5.5.5.5"),
		mkRec(t, dc, "mail", 300, "CNAME", "ghs.googlehosted.com."),
	}
	dc.Nameservers, err = models.ToNameservers(defaultNameServerNames)
	if err != nil {
		t.Fatal(err)
	}
	nameservers.AddNSRecords(dc) // Adds apex NS records (TTL 300).
	dc.Unmanaged = []*models.UnmanagedConfig{{LabelPattern: "@"}}
	dc.UnmanagedUnsafe = true

	// Existing config: whatever "Create some records" left in the zone, plus
	// Linode's injected read-only apex NS records.
	existing := models.Records{
		mkRec(t, dc, "@", 300, "A", "1.2.3.4"),
		mkRec(t, dc, "@", 300, "A", "2.3.4.5"),
		mkRec(t, dc, "@", 300, "TXT", "simple"),
		mkRec(t, dc, "bar", 300, "A", "5.5.5.5"),
		mkRec(t, dc, "mail", 300, "CNAME", "ghs.googlehosted.com."),
	}
	existing, err = appendDefaultNS(dc, existing)
	if err != nil {
		t.Fatal(err)
	}

	// Mimic GetZoneRecordsCorrections: normalize desired TTLs, then diff.
	for _, r := range dc.Records {
		r.TTL = fixTTL(r.TTL)
	}
	changes, actualChangeCount, err := diff2.ByRecord(existing, dc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if actualChangeCount != 0 {
		t.Errorf("expected 0 changes, got %d", actualChangeCount)
		for _, c := range changes {
			t.Logf("unexpected change: %s", c.MsgsJoined)
		}
	}
}

// TestApexNSNoSpuriousChanges verifies that the injected read-only apex NS
// placeholders match the desired apex NS records so a steady-state zone
// produces zero changes (no spurious MODIFY-TTL for the NS records).
func TestApexNSNoSpuriousChanges(t *testing.T) {
	dc, err := models.NewDomainConfig("dnscontroltest-linode.com")
	if err != nil {
		t.Fatal(err)
	}

	dc.Records = models.Records{
		mkRec(t, dc, "@", 300, "A", "1.2.3.4"),
		mkRec(t, dc, "bar", 300, "A", "5.5.5.5"),
	}
	dc.Nameservers, err = models.ToNameservers(defaultNameServerNames)
	if err != nil {
		t.Fatal(err)
	}
	nameservers.AddNSRecords(dc) // Adds apex NS records (TTL 300).

	existing := models.Records{
		mkRec(t, dc, "@", 300, "A", "1.2.3.4"),
		mkRec(t, dc, "bar", 300, "A", "5.5.5.5"),
	}
	existing, err = appendDefaultNS(dc, existing)
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range dc.Records {
		r.TTL = fixTTL(r.TTL)
	}
	changes, actualChangeCount, err := diff2.ByRecord(existing, dc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if actualChangeCount != 0 {
		t.Errorf("expected 0 changes, got %d", actualChangeCount)
		for _, c := range changes {
			t.Logf("unexpected change: %s", c.MsgsJoined)
		}
	}
}

func TestToRc(t *testing.T) {
	dc, err := models.NewDomainConfig("example.com")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		record     domainRecord
		wantTarget string
	}{
		{"A", domainRecord{Name: "www", Type: "A", Target: "192.0.2.1", TTLSec: 300}, "192.0.2.1"},
		{"MX", domainRecord{Name: "@", Type: "MX", Target: "mail.example.net", Priority: 10, TTLSec: 300}, "10 mail.example.net."},
		{"TXT", domainRecord{Name: "@", Type: "TXT", Target: "raw text", TTLSec: 300}, `"raw text"`},
		{"SRV", domainRecord{Name: "_sip._tcp", Type: "SRV", Target: "sip.example.net", Priority: 1, Weight: 2, Port: 5060, TTLSec: 300}, "1 2 5060 sip.example.net."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			record := tc.record
			rc, err := toRc(dc, &record)
			if err != nil {
				t.Fatal(err)
			}
			if got := rc.GetRDATA().String(); got != tc.wantTarget {
				t.Errorf("target = %q, want %q", got, tc.wantTarget)
			}
		})
	}
}
