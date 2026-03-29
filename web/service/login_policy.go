package service

import (
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/servercfg"
)

type LoginPolicySettings struct {
	BanTime      int64
	IPBanTime    int64
	UserBanTime  int64
	MaxFailTimes int
	MaxLoginBody int64
	MaxSkew      int64
}

func (s LoginPolicySettings) LoginDelayMillis() int64 {
	return s.BanTime * 1000
}

type LoginBanRecord struct {
	Key           string `json:"key"`
	FailTimes     int    `json:"fail_times"`
	LastLoginTime string `json:"last_login_time"`
	IsBanned      bool   `json:"is_banned"`
	BanType       string `json:"ban_type"`
}

type LoginPolicyService interface {
	Settings() LoginPolicySettings
	IsIPBanned(ip string) bool
	IsUserBanned(username string) bool
	RecordFailure(key string, explicit bool)
	RemoveBan(key string) bool
	RemoveAllBans()
	Clean(force bool)
	BanList() []LoginBanRecord
}

type DefaultLoginPolicy struct {
	ConfigProvider func() *servercfg.Snapshot
	records        sync.Map
}

var sharedLoginPolicy = NewDefaultLoginPolicy(servercfg.Current)

type loginFailureRecord struct {
	mu                sync.Mutex
	hasLoginFailTimes int
	lastLoginTime     time.Time
}

func NewDefaultLoginPolicy(provider func() *servercfg.Snapshot) *DefaultLoginPolicy {
	return &DefaultLoginPolicy{ConfigProvider: provider}
}

func SharedLoginPolicy() *DefaultLoginPolicy {
	return sharedLoginPolicy
}

func (s *DefaultLoginPolicy) Settings() LoginPolicySettings {
	cfg := s.config()
	return LoginPolicySettings{
		BanTime:      cfg.Security.LoginBanTime,
		IPBanTime:    cfg.Security.LoginIPBanTime,
		UserBanTime:  cfg.Security.LoginUserBanTime,
		MaxFailTimes: cfg.Security.LoginMaxFailTimes,
		MaxLoginBody: cfg.Security.LoginMaxBody,
		MaxSkew:      cfg.Security.LoginMaxSkew,
	}
}

func (s *DefaultLoginPolicy) IsIPBanned(ip string) bool {
	return s.isBanned(ip, s.Settings().IPBanTime)
}

func (s *DefaultLoginPolicy) IsUserBanned(username string) bool {
	return s.isBanned(username, s.Settings().UserBanTime)
}

func (s *DefaultLoginPolicy) RecordFailure(key string, explicit bool) {
	if !explicit || key == "" {
		return
	}
	now := time.Now()
	value, loaded := s.records.LoadOrStore(key, &loginFailureRecord{hasLoginFailTimes: 1, lastLoginTime: now})
	if loaded {
		current := value.(*loginFailureRecord)
		current.mu.Lock()
		current.lastLoginTime = now
		current.hasLoginFailTimes++
		current.mu.Unlock()
	}
}

func (s *DefaultLoginPolicy) RemoveBan(key string) bool {
	if key == "" {
		return false
	}
	if _, ok := s.records.Load(key); ok {
		s.records.Delete(key)
		return true
	}
	return false
}

func (s *DefaultLoginPolicy) RemoveAllBans() {
	s.records.Range(func(key, _ interface{}) bool {
		s.records.Delete(key)
		return true
	})
}

func (s *DefaultLoginPolicy) Clean(force bool) {
	if rand.Intn(100) != 1 && !force {
		return
	}

	settings := s.Settings()
	now := time.Now()
	s.records.Range(func(key, value interface{}) bool {
		currentKey := key.(string)
		current := value.(*loginFailureRecord)

		ttl := settings.UserBanTime
		if net.ParseIP(currentKey) != nil {
			ttl = settings.IPBanTime
		}

		current.mu.Lock()
		last := current.lastLoginTime
		current.mu.Unlock()

		if now.Unix()-last.Unix() >= ttl {
			s.records.Delete(key)
		}
		return true
	})
}

func (s *DefaultLoginPolicy) BanList() []LoginBanRecord {
	settings := s.Settings()
	var list []LoginBanRecord
	now := time.Now()

	s.records.Range(func(key, value interface{}) bool {
		currentKey := key.(string)
		current := value.(*loginFailureRecord)

		banType := "username"
		ttl := settings.UserBanTime
		if net.ParseIP(currentKey) != nil {
			banType = "ip"
			ttl = settings.IPBanTime
		}

		current.mu.Lock()
		fail := current.hasLoginFailTimes
		last := current.lastLoginTime
		current.mu.Unlock()

		duration := now.Unix() - last.Unix()
		isBanned := duration < settings.BanTime || (fail >= settings.MaxFailTimes && duration < ttl)
		list = append(list, LoginBanRecord{
			Key:           currentKey,
			FailTimes:     fail,
			LastLoginTime: last.Format("2006-01-02 15:04:05"),
			IsBanned:      isBanned,
			BanType:       banType,
		})
		return true
	})
	return list
}

func (s *DefaultLoginPolicy) isBanned(key string, ttl int64) bool {
	if key == "" {
		return false
	}
	settings := s.Settings()
	if value, ok := s.records.Load(key); ok {
		current := value.(*loginFailureRecord)
		current.mu.Lock()
		defer current.mu.Unlock()

		duration := time.Now().Unix() - current.lastLoginTime.Unix()
		if duration < settings.BanTime {
			logs.Warn("%s request rate too high, login blocked", key)
			return true
		}
		if duration >= ttl {
			current.hasLoginFailTimes = 0
		}
		if current.hasLoginFailTimes >= settings.MaxFailTimes {
			logs.Warn("%s has reached maximum failed attempts, login blocked", key)
			return true
		}
	}
	return false
}

func (s *DefaultLoginPolicy) IsBannedForTTL(key string, ttl int64) bool {
	return s.isBanned(key, ttl)
}

func (s *DefaultLoginPolicy) config() *servercfg.Snapshot {
	if s != nil && s.ConfigProvider != nil {
		if cfg := s.ConfigProvider(); cfg != nil {
			return cfg
		}
	}
	return servercfg.Current()
}
