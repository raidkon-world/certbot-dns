package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRecordsFromZoneFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com.zone")
	const sample = `$TTL 3600
$ORIGIN example.com.

www	3600	IN	A	89.208.33.248
@	3600	IN	MX	10	emx.mail.ru.
_acme-challenge	3600	IN	TXT	"token-one"
@	3600	IN	TXT	"hello"
dkim	3600	IN	TXT	"one-chunk"
`
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := loadRecordsFromZoneFile(path, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 5 {
		t.Fatalf("records = %d, want 5", len(recs))
	}
	var wwwA, mx, txt bool
	for _, r := range recs {
		switch {
		case r.Name == "www" && r.Type == "A" && r.Value == "89.208.33.248":
			wwwA = true
		case r.Name == "@" && r.Type == "MX" && r.Priority == 10 && r.Value == "emx.mail.ru":
			mx = true
		case r.Name == "dkim" && r.Type == "TXT" && r.Value == "one-chunk":
			txt = true
		}
	}
	if !wwwA || !mx || !txt {
		t.Fatalf("parsed subset missing: wwwA=%v mx=%v txt=%v", wwwA, mx, txt)
	}
}

func TestLoadRealZetepZoneExport(t *testing.T) {
	path := "/var/www/zetep/zetep-workspace/docs/zetep.com.zone"
	if _, err := os.Stat(path); err != nil {
		t.Skip("нет файла zetep.com.zone в окружении")
	}
	recs, err := loadRecordsFromZoneFile(path, "zetep.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) < 30 {
		t.Fatalf("records = %d, ожидали ~33 из экспорта", len(recs))
	}
}

func TestLoadPackagingExampleZone(t *testing.T) {
	path := filepath.Join("..", "packaging", "example.com.zone")
	if _, err := os.Stat(path); err != nil {
		t.Skip("packaging/example.com.zone not found")
	}
	recs, err := loadRecordsFromZoneFile(path, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) < 3 {
		t.Fatalf("records = %d", len(recs))
	}
}

func TestParseFileMasterPath(t *testing.T) {
	p, err := parseFileMasterPath("file:///var/www/example.com.zone")
	if err != nil {
		t.Fatal(err)
	}
	if p != "/var/www/example.com.zone" {
		t.Fatalf("path = %q", p)
	}
}

func TestTokenizeZoneLineQuotedTXT(t *testing.T) {
	line := `www 3600 IN TXT "hello world" "part2"`
	tokens, err := tokenizeZoneLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) < 5 {
		t.Fatalf("tokens = %v", tokens)
	}
	val := parseZoneTXTValue(strings.Join(tokens[4:], " "))
	if !strings.Contains(val, "helloworld") && !strings.Contains(val, "hello worldpart2") {
		t.Fatalf("value = %q", val)
	}
}

func TestParseZoneRecordLineCNAME(t *testing.T) {
	rec, err := parseZoneRecordLine(`cdn 3600 IN CNAME target.example.com.`, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Type != "CNAME" || rec.Value != "target.example.com" {
		t.Fatalf("rec = %+v", rec)
	}
}

func TestLoadRecordsOriginMismatch(t *testing.T) {
	path := writeTestZoneFile(t, "z.zone", `$ORIGIN other.com.
@ IN A 1.2.3.4
`)
	_, err := loadRecordsFromZoneFile(path, "example.com")
	if err == nil || !strings.Contains(err.Error(), "$ORIGIN") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRecordsSkipsCommentsAndDirectives(t *testing.T) {
	path := writeTestZoneFile(t, "z.zone", `; comment
$TTL 120
$ORIGIN example.com.
; another
@ 120 IN A 1.2.3.4
`)
	recs, err := loadRecordsFromZoneFile(path, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].TTL != 120*time.Second {
		t.Fatalf("recs = %+v", recs)
	}
}

func TestNormalizeZoneRecordName(t *testing.T) {
	if normalizeZoneRecordName("@", "example.com") != "@" {
		t.Fatal()
	}
	if normalizeZoneRecordName("www.example.com", "example.com") != "www" {
		t.Fatal()
	}
}

func TestParseZoneTTL(t *testing.T) {
	d, err := parseZoneTTL("3600")
	if err != nil || d != 3600*time.Second {
		t.Fatalf("d=%v err=%v", d, err)
	}
}
