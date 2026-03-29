package service

import (
	"strings"

	"github.com/djylb/nps/lib/file"
)

type GlobalService interface {
	Save(SaveGlobalInput) error
	Get() *file.Glob
	BanList() []LoginBanRecord
	Unban(key string) bool
	UnbanAll()
	CleanBans()
}

type DefaultGlobalService struct {
	LoginPolicy LoginPolicyService
	Backend     Backend
}

type SaveGlobalInput struct {
	GlobalBlackIPList string
}

func (s DefaultGlobalService) Save(input SaveGlobalInput) error {
	globalBlackIPList := UniqueStringsPreserveOrder(strings.Split(input.GlobalBlackIPList, "\r\n"))
	return s.repo().SaveGlobal(&file.Glob{BlackIpList: globalBlackIPList})
}

func (s DefaultGlobalService) Get() *file.Glob {
	return s.repo().GetGlobal()
}

func (s DefaultGlobalService) BanList() []LoginBanRecord {
	return s.loginPolicy().BanList()
}

func (s DefaultGlobalService) Unban(key string) bool {
	return s.loginPolicy().RemoveBan(key)
}

func (s DefaultGlobalService) UnbanAll() {
	s.loginPolicy().RemoveAllBans()
}

func (s DefaultGlobalService) CleanBans() {
	s.loginPolicy().Clean(true)
}

func (s DefaultGlobalService) loginPolicy() LoginPolicyService {
	if s.LoginPolicy != nil {
		return s.LoginPolicy
	}
	return SharedLoginPolicy()
}

func (s DefaultGlobalService) repo() Repository {
	if s.Backend.Repository != nil {
		return s.Backend.Repository
	}
	return DefaultBackend().Repository
}
