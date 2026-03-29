package controllers

import webservice "github.com/djylb/nps/web/service"

var BanTime int64
var IpBanTime int64
var UserBanTime int64
var MaxFailTimes int
var MaxLoginBody int64
var MaxSkew int64

type BanRecord = webservice.LoginBanRecord

func InitLogin() {
	settings := webservice.SharedLoginPolicy().Settings()
	BanTime = settings.BanTime
	IpBanTime = settings.IPBanTime
	UserBanTime = settings.UserBanTime
	MaxFailTimes = settings.MaxFailTimes
	MaxLoginBody = settings.MaxLoginBody
	MaxSkew = settings.MaxSkew
}

func IfLoginFail(key string, explicit bool) {
	webservice.SharedLoginPolicy().RecordFailure(key, explicit)
}

func IsLoginBan(key string, ttl int64) bool {
	return webservice.SharedLoginPolicy().IsBannedForTTL(key, ttl)
}

func GetLoginBanList() []BanRecord {
	return webservice.SharedLoginPolicy().BanList()
}

func RemoveLoginBan(key string) bool {
	return webservice.SharedLoginPolicy().RemoveBan(key)
}

func RemoveAllLoginBan() {
	webservice.SharedLoginPolicy().RemoveAllBans()
}

func CleanBanRecord(force bool) {
	webservice.SharedLoginPolicy().Clean(force)
}
