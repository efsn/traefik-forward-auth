package internal

import (
	"net/http"
	"net/url"

	"github.com/efsn/traefik-forward-auth/internal/provider"
	"github.com/sirupsen/logrus"
	"github.com/traefik/traefik/v2/pkg/rules"
)

// Server definition
type Server struct {
	router *rules.Router
}

// NewServer build server
func NewServer() *Server {
	s := &Server{}
	s.setup()
	return s
}

// DefaultHandler overwrite the request from forward request
func (r *Server) DefaultHandler(rw http.ResponseWriter, rq *http.Request) {
	rq.Method = rq.Header.Get("X-Forwarded-Method")
	rq.Host = rq.Header.Get("X-Forwarded-Host")

	if _, ok := rq.Header["X-Forwarded-Uri"]; ok {
		rq.URL, _ = url.Parse(rq.Header.Get("X-Forwarded-Uri"))
	}

	r.router.ServeHTTP(rw, rq)
}

// AllowHandler allow handler
func (r *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(rw http.ResponseWriter, rq *http.Request) {
		r.logger(rq, "Allow", rule, "Allowing request")
		rw.WriteHeader(200)
	}
}

// AuthHandler authorize request
func (r *Server) AuthHandler(provider, rule string) http.HandlerFunc {
	p, _ := config.GetConfiguredProvider(provider)
	return func(rw http.ResponseWriter, rq *http.Request) {
		log := r.logger(rq, "Auth", rule, "Authenticating request")

		ck, err := rq.Cookie(config.CookieName)
		if err != nil {
			r.authRedirect(log, rw, rq, p)
			return
		}

		email, err := ValidateCookie(rq, ck)
		if err != nil {
			if err.Error() == "Cookie has expired" {
				log.Info("Cookie has expired")
				r.authRedirect(log, rw, rq, p)
			} else {
				log.WithField("error", err).Warn("Invalid cookie")
				http.Error(rw, "Not authorized", 401)
			}
			return
		}

		if valid := ValidateEmail(email, rule); !valid {
			log.WithField("email", email).Warn("Invalid email")
			http.Error(rw, "Not authorzed", 401)
			return
		}

		log.Debug("Allowing valid request")
		rw.Header().Set("X-Forwarded-User", email)
		rw.WriteHeader(200)
	}
}

// AuthCallbackHandler authorize  callback handler
func (r *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(rw http.ResponseWriter, rq *http.Request) {
		log := r.logger(rq, "AuthCallback", "default", "Handling  callback")

		state := rq.URL.Query().Get("state")
		if err := ValidateState(state); err != nil {
			log.WithField("error", err).Warn(rw, "Not authorzied", 401)
			return
		}

		ck, err := FindCSRFCookie(rq, state)
		if err != nil {
			log.Info("Missing csrf cookie")
			http.Error(rw, "Not authorized", 401)
			return
		}

		valid, name, redirect, err := ValidateCSRFCookie(ck, state)
		if !valid {
			log.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": ck,
			}).Warn("Error validating csrf cookie")
			http.Error(rw, "Not authorized", 401)
			return
		}

		p, err := config.GetConfiguredProvider(name)
		if err != nil {
			log.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": ck,
				"provider":    name,
			}).Warn("Invalid provider in csrf cookie")
			http.Error(rw, "Not authorized", 401)
		}

		http.SetCookie(rw, ClearCSRFCookie(rq, ck))

		token, err := p.ExchangeCode(redirectURI(rq), rq.URL.Query().Get("code"))
		if err != nil {
			log.WithField("error", err).Error("Code exchange failed with provider")
			http.Error(rw, "Service unavailable", 503)
			return
		}

		user, err := p.GetUser(token)
		if err != nil {
			log.WithField("error", err).Error("Error get user")
			http.Error(rw, "Service unavailable", 503)
			return
		}

		http.SetCookie(rw, MakeCookie(rq, user.Email))
		log.WithFields(logrus.Fields{
			"provider": name,
			"redirect": redirect,
			"user":     user.Email,
		}).Info("Successfully generated auth cookie, redirected user")

		http.Redirect(rw, rq, redirect, http.StatusTemporaryRedirect)
	}
}

// LogoutHandler logout request handler
func (r *Server) LogoutHandler() http.HandlerFunc {
	return func(rw http.ResponseWriter, rq *http.Request) {
		http.SetCookie(rw, ClearCookie(rq))
		log := r.logger(rq, "Logout", "default", "Handling logout")
		log.Info("Logout user")
		if config.LogoutRedirect != "" {
			http.Redirect(rw, rq, config.LogoutRedirect, http.StatusTemporaryRedirect)
		} else {
			http.Error(rw, "You have logout", 401)
		}
	}
}

func (r *Server) setup() {
	var err error
	r.router, err = rules.NewRouter()
	if err != nil {
		logger.Fatal(err)
	}

	for k, v := range config.Rules {
		matchRule := v.format()
		if v.Action == "allow" {
			r.router.AddRoute(matchRule, 1, r.AllowHandler(k))
		} else {
			r.router.AddRoute(matchRule, 1, r.AuthHandler(v.Provider, k))
		}

		r.router.Handle(config.Path, r.AuthCallbackHandler())
		r.router.Handle(config.Path+"/logout", r.LogoutHandler())
		if config.DefaultAction == "allow" {
			r.router.NewRoute().Handler(r.AllowHandler("default"))
		} else {
			r.router.NewRoute().Handler(r.AuthHandler(config.DefaultProvider, "defaut"))
		}
	}
}

func (r *Server) logger(rq *http.Request, handler, rule, msg string) *logrus.Entry {
	log := logger.WithFields(logrus.Fields{
		"handler":   handler,
		"rule":      rule,
		"method":    rq.Header.Get("X-Forwarded-Method"),
		"proto":     rq.Header.Get("X-Forwarded-Proto"),
		"host":      rq.Header.Get("X-Forwarded-Host"),
		"uri":       rq.Header.Get("X-Forwarded-Uri"),
		"source_ip": rq.Header.Get("X-Forwarded-For"),
	})

	log.WithFields(logrus.Fields{
		"cookies": rq.Cookies(),
	}).Debug(msg)

	return log
}

func (r *Server) authRedirect(log *logrus.Entry, rw http.ResponseWriter, rq *http.Request, p provider.Provider) {
	nonce, err := Nonce()
	if err != nil {
		log.WithField("error", err).Error("Error generate nonce")
		http.Error(rw, "Service unavailable", 503)
		return
	}

	csrf := MakeCSRFCookie(rq, nonce)
	http.SetCookie(rw, csrf)
	if !config.InsecureCookie && rq.Header.Get("X-Forwarded-Proto") != "https" {
		log.Warn("You are using \"secure\" cookies for a request that was not received via https. Which should either redirect to https or pass the \"insecure-cookie\" cookie option to permit cookies via http.")
	}

	loginURL := p.GetLoginURL(redirectURI(rq), MakeState(rq, p, nonce))
	http.Redirect(rw, rq, loginURL, http.StatusTemporaryRedirect)

	log.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
}
