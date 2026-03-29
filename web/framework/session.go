package framework

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/http"
	"sync"

	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/servercfg"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

const sessionName = "nps_session"

type sessionState struct {
	store   *sessions.CookieStore
	session *sessions.Session
	writer  http.ResponseWriter
	request *http.Request
}

var (
	sessionMu             sync.Mutex
	sessionStore          *sessions.CookieStore
	sessionConfigProvider = servercfg.Current
)

func InitSessionStore(cfg *servercfg.Snapshot) error {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if cfg == nil {
		cfg = currentSessionConfigLocked()
	}
	store, err := buildSessionStore(cfg)
	if err != nil {
		return err
	}
	sessionStore = store
	return nil
}

func SetSessionConfigProvider(provider func() *servercfg.Snapshot) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if provider == nil {
		sessionConfigProvider = servercfg.Current
		return
	}
	sessionConfigProvider = provider
}

func newSessionState(w http.ResponseWriter, r *http.Request, cfg *servercfg.Snapshot) (*sessionState, error) {
	sessionMu.Lock()
	if sessionStore == nil {
		store, err := buildSessionStore(cfg)
		if err != nil {
			sessionMu.Unlock()
			return nil, err
		}
		sessionStore = store
	}
	store := sessionStore
	sessionMu.Unlock()

	session, err := store.Get(r, sessionName)
	if err != nil {
		logs.Warn("Invalid web session cookie, resetting session: %v", err)
		_ = clearSessionCookie(store, w, r)
		session = newBlankSession(store)
	}
	return &sessionState{
		store:   store,
		session: session,
		writer:  w,
		request: r,
	}, nil
}

func EnsureSession(g *gin.Context) error {
	if sessionStateFromContext(g) != nil {
		return nil
	}
	session, err := newSessionState(g.Writer, g.Request, currentSessionConfig())
	if err != nil {
		return err
	}
	g.Set(sessionContextKey, session)
	return nil
}

func SessionValue(g *gin.Context, key string) interface{} {
	session := sessionStateFromContext(g)
	if session == nil {
		return nil
	}
	return session.Get(key)
}

func SetSessionValue(g *gin.Context, key string, value interface{}) error {
	if err := EnsureSession(g); err != nil {
		return err
	}
	session := sessionStateFromContext(g)
	if session == nil {
		return nil
	}
	session.Set(key, value)
	return nil
}

func DeleteSessionValue(g *gin.Context, key string) error {
	if err := EnsureSession(g); err != nil {
		return err
	}
	session := sessionStateFromContext(g)
	if session == nil {
		return nil
	}
	session.Delete(key)
	return nil
}

func sessionStateFromContext(g *gin.Context) *sessionState {
	if v, ok := g.Get(sessionContextKey); ok {
		if session, ok := v.(*sessionState); ok {
			return session
		}
	}
	return nil
}

func (s *sessionState) Get(key string) interface{} {
	if s == nil || s.session == nil {
		return nil
	}
	return s.session.Values[key]
}

func (s *sessionState) Set(key string, value interface{}) {
	if s == nil || s.session == nil {
		return
	}
	s.session.Values[key] = value
	_ = s.session.Save(s.request, s.writer)
}

func (s *sessionState) Delete(key string) {
	if s == nil || s.session == nil {
		return
	}
	delete(s.session.Values, key)
	_ = s.session.Save(s.request, s.writer)
}

func buildSessionStore(cfg *servercfg.Snapshot) (*sessions.CookieStore, error) {
	authKey, encKey, err := deriveSessionKeys(cfg)
	if err != nil {
		return nil, err
	}
	store := sessions.NewCookieStore(authKey, encKey)
	store.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	return store, nil
}

func clearSessionCookie(store *sessions.CookieStore, w http.ResponseWriter, r *http.Request) error {
	session := newBlankSession(store)
	session.Options.MaxAge = -1
	return session.Save(r, w)
}

func newBlankSession(store *sessions.CookieStore) *sessions.Session {
	session := sessions.NewSession(store, sessionName)
	if store != nil && store.Options != nil {
		options := *store.Options
		session.Options = &options
	}
	session.IsNew = true
	return session
}

func deriveSessionKeys(cfg *servercfg.Snapshot) ([]byte, []byte, error) {
	seed := fmt.Sprintf("%s|%s|%s|%s", cfg.Web.Username, cfg.Web.Password, cfg.Auth.Key, cfg.App.Name)
	if seed == "|||" {
		authKey := make([]byte, 32)
		encKey := make([]byte, 32)
		if _, err := rand.Read(authKey); err != nil {
			return nil, nil, err
		}
		if _, err := rand.Read(encKey); err != nil {
			return nil, nil, err
		}
		return authKey, encKey, nil
	}
	authSum := sha256.Sum256([]byte("auth:" + seed))
	encSum := sha256.Sum256([]byte("enc:" + seed))
	return authSum[:], encSum[:], nil
}

func currentSessionConfig() *servercfg.Snapshot {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	return currentSessionConfigLocked()
}

func currentSessionConfigLocked() *servercfg.Snapshot {
	if sessionConfigProvider != nil {
		if cfg := sessionConfigProvider(); cfg != nil {
			return cfg
		}
	}
	return servercfg.Current()
}
