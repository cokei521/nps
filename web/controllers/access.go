package controllers

import webservice "github.com/djylb/nps/web/service"

func ClientOwnsClient(clientID, targetID int) bool {
	return clientID > 0 && clientID == targetID
}

func ClientOwnsTunnel(clientID, tunnelID int) bool {
	return webservice.ClientOwnsTunnel(clientID, tunnelID)
}

func ClientOwnsHost(clientID, hostID int) bool {
	return webservice.ClientOwnsHost(clientID, hostID)
}
