package main

import "testing"

func TestCertProviderListUnmarshalString(t *testing.T) {
	var p certProviderList
	if err := p.UnmarshalTOML("  fv-main  "); err != nil {
		t.Fatal(err)
	}
	if len(p) != 1 || p[0] != "fv-main" {
		t.Fatalf("got %v", p)
	}
}

func TestCertProviderListUnmarshalArray(t *testing.T) {
	var p certProviderList
	if err := p.UnmarshalTOML([]any{"a", "b", "c"}); err != nil {
		t.Fatal(err)
	}
	if len(p) != 3 {
		t.Fatalf("got %v", p)
	}
}

func TestCertProviderListUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name  string
		input any
	}{
		{"int", 42},
		{"array non-string", []any{"ok", 1}},
		{"empty string in array", []any{"a", ""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p certProviderList
			if err := p.UnmarshalTOML(tc.input); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCertProviderListNamesDedupe(t *testing.T) {
	p := certProviderList{"fv", "ali", "fv", "  fv  "}
	got := p.names("")
	if len(got) != 2 || got[0] != "fv" || got[1] != "ali" {
		t.Fatalf("got %v", got)
	}
}

func TestCertProviderListNamesDefault(t *testing.T) {
	var empty certProviderList
	got := empty.names("")
	if len(got) != 1 || got[0] != defaultProviderName {
		t.Fatalf("got %v", got)
	}
}

func TestCertProviderListLabel(t *testing.T) {
	p := certProviderList{"a", "b"}
	if p.label() != "a,b" {
		t.Fatalf("label = %q", p.label())
	}
	if certProviderList(nil).label() != defaultProviderName {
		t.Fatalf("default label = %q", certProviderList(nil).label())
	}
}
