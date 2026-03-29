package api

type StatusMessageResponse struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
}

type StatusMessageIDResponse struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
	ID     int    `json:"id"`
}

type StatusNonceResponse struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
	Nonce  string `json:"nonce,omitempty"`
}

type StatusNonceBitsResponse struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
	Nonce  string `json:"nonce,omitempty"`
	Bits   int    `json:"bits"`
}

type StatusNonceCertResponse struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
	Nonce  string `json:"nonce,omitempty"`
	Cert   string `json:"cert,omitempty"`
}

type StatusNonceTimestampResponse struct {
	Status    int    `json:"status"`
	Msg       string `json:"msg"`
	Nonce     string `json:"nonce,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

type AuthKeyResponse struct {
	Status       int    `json:"status"`
	CryptAuthKey string `json:"crypt_auth_key,omitempty"`
	CryptType    string `json:"crypt_type,omitempty"`
}

type TimeResponse struct {
	Time int64 `json:"time"`
}

type CertResponse struct {
	Status int    `json:"status"`
	Cert   string `json:"cert,omitempty"`
}

type CodeResponse struct {
	Code int `json:"code"`
}

type CodeDataResponse struct {
	Code int `json:"code"`
	Data any `json:"data,omitempty"`
}

type CodeRTTResponse struct {
	Code int `json:"code"`
	RTT  int `json:"rtt"`
}

type TableResponse struct {
	Rows  any `json:"rows"`
	Total int `json:"total"`
}

type ClientListResponse struct {
	Rows       any    `json:"rows"`
	Total      int    `json:"total"`
	IP         string `json:"ip"`
	Addr       string `json:"addr"`
	BridgeType string `json:"bridgeType"`
	BridgePort int    `json:"bridgePort"`
}
