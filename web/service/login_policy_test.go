package service

import (
	"testing"

	"github.com/djylb/nps/lib/servercfg"
)

func TestDefaultLoginPolicyUsesConfigProvider(t *testing.T) {
	policy := NewDefaultLoginPolicy(func() *servercfg.Snapshot {
		return &servercfg.Snapshot{
			Security: servercfg.SecurityConfig{
				LoginBanTime:      7,
				LoginIPBanTime:    11,
				LoginUserBanTime:  13,
				LoginMaxFailTimes: 5,
				LoginMaxBody:      2048,
				LoginMaxSkew:      9000,
			},
		}
	})

	settings := policy.Settings()
	if settings.BanTime != 7 || settings.IPBanTime != 11 || settings.UserBanTime != 13 {
		t.Fatalf("Settings() returned unexpected ban settings: %+v", settings)
	}
	if settings.MaxFailTimes != 5 || settings.MaxLoginBody != 2048 || settings.MaxSkew != 9000 {
		t.Fatalf("Settings() returned unexpected limits: %+v", settings)
	}
}

func TestDefaultLoginPolicyBanLifecycle(t *testing.T) {
	policy := NewDefaultLoginPolicy(func() *servercfg.Snapshot {
		return &servercfg.Snapshot{
			Security: servercfg.SecurityConfig{
				LoginBanTime:      60,
				LoginIPBanTime:    60,
				LoginUserBanTime:  60,
				LoginMaxFailTimes: 3,
			},
		}
	})

	policy.RecordFailure("127.0.0.1", true)
	if !policy.IsIPBanned("127.0.0.1") {
		t.Fatal("IsIPBanned() = false, want true after explicit failure")
	}

	records := policy.BanList()
	if len(records) != 1 || records[0].BanType != "ip" || !records[0].IsBanned {
		t.Fatalf("BanList() = %+v, want one banned ip record", records)
	}

	if !policy.RemoveBan("127.0.0.1") {
		t.Fatal("RemoveBan() = false, want true")
	}
	if policy.IsIPBanned("127.0.0.1") {
		t.Fatal("IsIPBanned() = true after RemoveBan(), want false")
	}
}
