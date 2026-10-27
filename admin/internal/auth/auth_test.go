package auth

import (
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Fatal("right password rejected")
	}
	if VerifyPassword(h, "wrong") || VerifyPassword("garbage", "x") || VerifyPassword("", "") {
		t.Fatal("wrong password accepted")
	}
	if CheckPasswordStrength("") == nil || CheckPasswordStrength("short") != nil {
		t.Fatal("strength rule wrong")
	}
}

func TestSetupTokenNormalization(t *testing.T) {
	tok := NewSetupToken()
	if len(tok) != 19 || tok[4] != '-' {
		t.Fatalf("token shape %q", tok)
	}
	typed := " " + tok[:9] + " " + tok[10:] + " "
	if !EqualTokens(NormalizeSetupToken(tok), NormalizeSetupToken(typed)) {
		t.Fatalf("normalization failed: %q vs %q", tok, typed)
	}
	if EqualTokens(NormalizeSetupToken(tok), NormalizeSetupToken(NewSetupToken())) {
		t.Fatal("two tokens compared equal")
	}
}

func TestSessions(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	s := NewSessions()
	s.now = func() time.Time { return now }
	admin := s.Create(KindAdmin)
	setup := s.Create(KindSetup)
	if k, ok := s.Lookup(admin); !ok || k != KindAdmin {
		t.Fatal("admin session missing")
	}
	now = now.Add(16 * time.Minute)
	if _, ok := s.Lookup(setup); ok {
		t.Fatal("setup session outlived its TTL")
	}
	if _, ok := s.Lookup(admin); !ok {
		t.Fatal("admin session expired early")
	}
	now = now.Add(13 * time.Hour)
	if _, ok := s.Lookup(admin); ok {
		t.Fatal("idle admin session not expired")
	}
	a2 := s.Create(KindAdmin)
	for i := 0; i < 8; i++ { // keep it active past the absolute limit
		now = now.Add(23 * time.Hour)
		s.Lookup(a2)
	}
	if _, ok := s.Lookup(a2); ok {
		t.Fatal("absolute limit not enforced")
	}
	if _, ok := s.Lookup("nope"); ok {
		t.Fatal("unknown id accepted")
	}
}

func TestSessionsPersist(t *testing.T) {
	path := t.TempDir() + "/sessions.json"
	a := NewPersistentSessions(path)
	admin := a.Create(KindAdmin)
	setup := a.Create(KindSetup)
	b := NewPersistentSessions(path)
	if k, ok := b.Lookup(admin); !ok || k != KindAdmin {
		t.Fatal("admin session did not survive a restart")
	}
	if _, ok := b.Lookup(setup); ok {
		t.Fatal("setup session was persisted")
	}
	b.DeleteAll()
	if _, ok := NewPersistentSessions(path).Lookup(admin); ok {
		t.Fatal("DeleteAll not persisted")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	l := NewLimiter()
	l.now = func() time.Time { return now }
	for i := 0; i < 4; i++ {
		l.Fail("a")
	}
	if l.Wait("a") != 0 {
		t.Fatal("locked too early")
	}
	l.Fail("a")
	if w := l.Wait("a"); w != 2*time.Second {
		t.Fatalf("first delay %v", w)
	}
	l.Fail("a")
	if w := l.Wait("a"); w != 4*time.Second {
		t.Fatalf("second delay %v", w)
	}
	if l.Wait("b") != 0 {
		t.Fatal("another client was locked by a's failures")
	}
	for i := 0; i < 20; i++ {
		l.Fail("a")
	}
	if w := l.Wait("a"); w != maxDelay {
		t.Fatalf("cap %v", w)
	}
	l.Succeed("a")
	if l.Wait("a") != 0 {
		t.Fatal("success did not clear")
	}
	// Rotating addresses hits the global backstop.
	for i := 0; i < globalFreeAttempts; i++ {
		l.Fail("x" + string(rune('A'+i%26)) + string(rune('a'+i/26)))
	}
	if l.Wait("fresh") == 0 {
		t.Fatal("global backstop did not engage")
	}
}
