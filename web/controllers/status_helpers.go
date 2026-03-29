package controllers

import webservice "github.com/djylb/nps/web/service"

func ChangeTunnelStatus(id int, name, action string) error {
	return webservice.ChangeTunnelStatus(id, name, action)
}

func ChangeHostStatus(id int, name, action string) error {
	return webservice.ChangeHostStatus(id, name, action)
}
