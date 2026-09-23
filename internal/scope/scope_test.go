package scope

import "testing"

func TestAllows(t *testing.T) {
	s := New([]string{"app.example.com", "*.internal.example.com"}, []string{"secret.internal.example.com"})

	cases := []struct {
		url  string
		want bool
	}{
		{"https://app.example.com/admin", true},
		{"http://app.example.com:8080/x", true},
		{"https://api.internal.example.com/", true},
		{"https://internal.example.com/", true},
		{"https://secret.internal.example.com/", false}, // excluded
		{"https://evil.com/", false},
		{"https://app.example.com.evil.com/", false}, // suffix trick
		{"not a url", false},
	}
	for _, c := range cases {
		if got := s.Allows(c.url); got != c.want {
			t.Errorf("Allows(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestEmptyScopeDeniesAll(t *testing.T) {
	s := New(nil, nil)
	if s.Allows("https://anything.com/") {
		t.Fatal("empty scope must deny everything")
	}
	if err := s.Check("https://anything.com/"); err == nil {
		t.Fatal("empty scope Check must return an error")
	}
}

func TestCheckOutOfScopeError(t *testing.T) {
	s := New([]string{"good.com"}, nil)
	if err := s.Check("https://bad.com/"); err == nil {
		t.Fatal("expected out-of-scope error")
	}
	if err := s.Check("https://good.com/x"); err != nil {
		t.Fatalf("expected in-scope, got error: %v", err)
	}
}
