package controllers

import (
	"github.com/djylb/nps/lib/servercfg"
	webservice "github.com/djylb/nps/web/service"
)

func IsValidAuthKey(configKey, md5Key string, timestamp int, nowUnix int64) bool {
	return webservice.ValidAuthKey(configKey, md5Key, timestamp, nowUnix)
}

func GetBestBridge(ip string) (bridgeType, bridgeAddr, bridgeIP, bridgePort string) {
	bridge := webservice.BestBridge(servercfg.Current(), ip)
	return bridge.Type, bridge.Addr, bridge.IP, bridge.Port
}
