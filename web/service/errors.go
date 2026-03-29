package service

import "errors"

var (
	ErrClientQRCodeTextRequired = errors.New("missing qr code text")
	ErrClientModifyFailed       = errors.New("client modify failed")
	ErrClientVKeyDuplicate      = errors.New("client verify key duplicate")
	ErrWebUsernameDuplicate     = errors.New("client web username duplicate")
	ErrInvalidRegistration      = errors.New("invalid registration")
	ErrReservedUsername         = errors.New("reserved username")
	ErrClientNotFound           = errors.New("client not found")
	ErrTunnelNotFound           = errors.New("tunnel not found")
	ErrHostNotFound             = errors.New("host not found")
	ErrHostExists               = errors.New("host already exists")
	ErrModeRequired             = errors.New("mode is required")
	ErrPortUnavailable          = errors.New("port unavailable")
	ErrTunnelLimitExceeded      = errors.New("tunnel limit exceeded")
	ErrInvalidCredentials       = errors.New("invalid credentials")
	ErrUnauthenticated          = errors.New("unauthenticated")
	ErrForbidden                = errors.New("forbidden")
	ErrPageNotFound             = errors.New("page not found")
)
