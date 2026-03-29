package controllers

import (
	"testing"

	webservice "github.com/djylb/nps/web/service"
)

func TestLoginStateCompatibilityUsesSharedPolicy(t *testing.T) {
	policy := webservice.SharedLoginPolicy()
	policy.RemoveAllBans()
	t.Cleanup(policy.RemoveAllBans)

	IfLoginFail("127.0.0.1", true)
	if !policy.IsIPBanned("127.0.0.1") {
		t.Fatal("shared login policy should see compatibility wrapper failure records")
	}

	RemoveAllLoginBan()
	if policy.IsIPBanned("127.0.0.1") {
		t.Fatal("RemoveAllLoginBan() should clear shared login policy state")
	}
}
