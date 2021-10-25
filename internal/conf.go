package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/efsn/traefik-forward-auth/internal/provider"
	"github.com/thomseddon/go-flags"
)

var conf *Conf

// Conf auth global configuration
type Conf struct {
	LogLevel  string `long:"log-level" env:"LOG_LEVEL" default:"warn" choice:"trace" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal" choice:"panic" description:"Log level"`
	LogFormat string `long:"log-format"  env:"LOG_FORMAT" default:"text" choice:"text" choice:"json" choice:"pretty" description:"Log format"`

	AuthHost               string               `long:"auth-host" env:"AUTH_HOST" description:"Single host to use when returning from 3rd party auth"`
	Configure              func(s string) error `long:"config" env:"CONFIG" description:"Path to config file" json:"-"`
	CookieDomains          []CookieDomain       `long:"cookie-domain" env:"COOKIE_DOMAIN" env-delim:"," description:"Domain to set auth cookie on, can be set multiple times"`
	InsecureCookie         bool                 `long:"insecure-cookie" env:"INSECURE_COOKIE" description:"Use insecure cookies"`
	CookieName             string               `long:"cookie-name" env:"COOKIE_NAME" default:"_forward_auth" description:"Cookie Name"`
	CSRFCookieName         string               `long:"csrf-cookie-name" env:"CSRF_COOKIE_NAME" default:"_forward_auth_csrf" description:"CSRF Cookie Name"`
	DefaultAction          string               `long:"default-action" env:"DEFAULT_ACTION" default:"auth" choice:"auth" choice:"allow" description:"Default action"`
	DefaultProvider        string               `long:"default-provider" env:"DEFAULT_PROVIDER" default:"google" choice:"google" choice:"oidc" choice:"generic-oauth" description:"Default provider"`
	Domains                CommaSeparatedList   `long:"domain" env:"DOMAIN" env-delim:"," description:"Only allow given email domains, can be set multiple times"`
	LifetimeString         int                  `long:"lifetime" env:"LIFETIME" default:"43200" description:"Lifetime in seconds"`
	LogoutRedirect         string               `long:"logout-redirect" env:"LOGOUT_REDIRECT" description:"URL to redirect to following logout"`
	MatchWhitelistOrDomain bool                 `long:"match-whitelist-or-domain" env:"MATCH_WHITELIST_OR_DOMAIN" description:"Allow users that match *either* whitelist or domain (enabled by default in v3)"`
	Path                   string               `long:"url-path" env:"URL_PATH" default:"/_oauth" description:"Callback URL Path"`
	SecretString           string               `long:"secret" env:"SECRET" description:"Secret used for signing (required)" json:"-"`
	Whitelist              CommaSeparatedList   `long:"whitelist" env:"WHITELIST" env-delim:"," description:"Only allow given email addresses, can be set multiple times"`
	Port                   int                  `long:"port" env:"PORT" default:"5137" description:"Port to listen on"`

	Providers provider.Providers `group:"providers" namespace:"providers" env-namespace:"PROVIDERS"`
	Rules     map[string]*Rule   `long:"rule.<name>.<param>" description:"Rule definitions, param can be: \"action\", \"rule\" or \"provider\""`

	// Filled during transformations
	Secret   []byte `json:"-"`
	Lifetime time.Duration

	// Legacy
	CookieDomainsLegacy CookieDomains `long:"cookie-domains" env:"COOKIE_DOMAINS" description:"DEPRECATED - Use \"cookie-domain\""`
	CookieSecretLegacy  string        `long:"cookie-secret" env:"COOKIE_SECRET" description:"DEPRECATED - Use \"secret\""  json:"-"`
	CookieSecureLegacy  string        `long:"cookie-secure" env:"COOKIE_SECURE" description:"DEPRECATED - Use \"insecure-cookie\""`
	ClientIDLegacy      string        `long:"client-id" env:"CLIENT_ID" description:"DEPRECATED - Use \"providers.google.client-id\""`
	ClientSecretLegacy  string        `long:"client-secret" env:"CLIENT_SECRET" description:"DEPRECATED - Use \"providers.google.client-id\""  json:"-"`
	PromptLegacy        string        `long:"prompt" env:"PROMPT" description:"DEPRECATED - Use \"providers.google.prompt\""`
}

// Rule rule definition
type Rule struct {
	Action    string
	Rule      string
	Provider  string
	Whitelist CommaSeparatedList
	Domains   CommaSeparatedList
}

// CommaSeparatedList slice
type CommaSeparatedList []string

// NewRule build rule
func NewRule() *Rule {
	return &Rule{
		Action: "action",
	}
}

// NewGlobalConf build conf
func NewGlobalConf() *Conf {
	var err error
	conf, err = NewConf(os.Args[1:])
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
	return conf
}

// NewParsedConf build parsed conf
func NewParsedConf() *Conf {
	var err error
	conf, err = NewConf(os.Args[1:])
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
	return conf
}

// NewConf build conf
func NewConf(args []string) (*Conf, error) {
	cf := &Conf{
		Rules: map[string]*Rule{},
	}

	if err := cf.parseFlags(args); err != nil {
		return cf, err
	}

	// TODO: as log flags have now been parsed maybe we should return here so
	// any further errors can be logged via logrus instead of printed?
	err := cf.setup()
	return cf, err
}

// Validate check conf
func (r *Conf) Validate() {
	if len(r.Secret) == 0 {
		log.Fatal("\"secret\" option must be set")
	}

	if err := r.setupProvider(r.DefaultProvider); err != nil {
		log.Fatal(err)
	}

	for _, rule := range r.Rules {
		if err := rule.Validate(r); err != nil {
			log.Fatal(err)
		}
	}
}

// GetProvider get provider from conf
func (r *Conf) GetProvider(name string) (provider.Provider, error) {
	switch name {
	case "google":
		return &r.Providers.Google, nil
	case "oidc":
		return &r.Providers.OIDC, nil
	case "generic-oauth":
		return &r.Providers.GenericOAuth, nil
	}
	return nil, fmt.Errorf("Unknown provider: %s", name)
}

// GetConfiguredProvider get provider
func (r *Conf) GetConfiguredProvider(name string) (provider.Provider, error) {
	if !r.providerConfigured(name) {
		return nil, fmt.Errorf("Unconfigured provider: %s", name)
	}

	return r.GetProvider(name)
}

// Validate rule validate action
func (r *Rule) Validate(cf *Conf) error {
	if r.Action != "auth" && r.Action != "allow" {
		return errors.New("invalid rule action, must be \"auth\" or \"allow\"")
	}
	return cf.setupProvider(r.Provider)
}

// UnmarshalFlag unmarshal flag
func (r *CommaSeparatedList) UnmarshalFlag(s string) error {
	*r = append(*r, strings.Split(s, ",")...)
	return nil
}

// MarshalFlag marshal flag
func (r *CommaSeparatedList) MarshalFlag() (string, error) {
	return strings.Join(*r, ","), nil
}

func (r *Conf) String() string {
	jsonConf, _ := json.Marshal(r)
	return string(jsonConf)
}

func (r *Rule) formattedRule() string {
	return strings.ReplaceAll(r.Rule, "Host(", "HostRegexp(")
}

func (r *Conf) setup() error {
	for _, rule := range r.Rules {
		if rule.Provider == "" {
			rule.Provider = r.DefaultProvider
		}
	}

	// Backwards compatability
	if r.CookieSecureLegacy != "" && r.SecretString == "" {
		fmt.Println("cookie-secret conf option is deprecated, please use secret")
		r.SecretString = r.CookieSecureLegacy
	}

	if r.ClientIDLegacy != "" {
		r.Providers.Google.ClientID = r.ClientSecretLegacy
	}

	if r.PromptLegacy != "" {
		fmt.Println("prompt conf option is deprecated, please use providers.google.prompt")
		r.Providers.Google.Prompt = r.PromptLegacy
	}

	if r.CookieSecureLegacy != "" {
		fmt.Println("cookie-secure conf option is deprecated, please use insecure-cookie")
		secure, err := strconv.ParseBool(r.CookieSecureLegacy)
		if err != nil {
			return err
		}
		r.InsecureCookie = !secure
	}

	if len(r.CookieDomainsLegacy) > 0 {
		fmt.Println("cookie-secure conf option is deprecated, please use insecure-cookie")
		r.CookieDomains = append(r.CookieDomains, r.CookieDomainsLegacy...)
	}

	if len(r.Path) > 0 && r.Path[0] != '/' {
		r.Path = "/" + r.Path
	}

	r.Secret = []byte(r.SecretString)
	r.Lifetime = time.Second * time.Duration(r.LifetimeString)

	return nil
}

func (r *Conf) parseFlags(args []string) error {
	p := flags.NewParser(r, flags.Default|flags.IniUnknownOptionHandler)
	p.UnknownOptionHandler = r.parseUnknownFlag

	i := flags.NewIniParser(p)
	r.Configure = func(s string) error {
		err := i.ParseFile(s)
		if err != nil && strings.Contains(err.Error(), "malformed key=value") {
			converted, convertErr := convertLegacyToIni(s)
			if convertErr != nil {
				return err
			}
			fmt.Println("conf format deprecated, please use ini format")
			return i.Parse(converted)
		}
		return err
	}

	if _, err := p.ParseArgs(args); err != nil {
		return handleFlagError(err)
	}
	return nil
}

func (r *Conf) parseUnknownFlag(opt string, arg flags.SplitArgument, args []string) ([]string, error) {
	parts := strings.Split(opt, ".")
	if len(parts) == 3 && parts[0] == "rule" {
		name := parts[1]
		if len(name) == 0 {
			return args, errors.New("route name is  required")
		}

		v, ok := arg.Value()
		if !ok && len(args) > 1 {
			v = args[0]
			args = args[1:]
		}

		if len(v) == 0 {
			return args, errors.New("route param value is required")
		}

		if v[0] == '"' {
			var err error
			v, err = strconv.Unquote(v)
			if err != nil {
				return args, err
			}
		}

		rule, ok := r.Rules[name]
		if !ok {
			rule = NewRule()
			r.Rules[name] = rule
		}

		switch parts[2] {
		case "action":
			rule.Action = v
		case "rule":
			rule.Rule = v
		case "provider":
			rule.Provider = v
		case "whitelist":
			list := CommaSeparatedList{}
			list.UnmarshalFlag(v)
			rule.Domains = list
		case "domains":

		default:
			return args, fmt.Errorf("invalid route param: %v", opt)
		}
	} else {
		return args, fmt.Errorf("unknown flag: %v", opt)
	}
	return args, nil
}

func handleFlagError(err error) error {
	flagsErr, ok := err.(*flags.Error)
	if ok && flagsErr.Type == flags.ErrHelp {
		os.Exit(0)
	}
	return err
}

var legacyFileFormat = regexp.MustCompile(`(?m)^([a-z-]+) (.*)$`)

func convertLegacyToIni(name string) (io.Reader, error) {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(legacyFileFormat.ReplaceAll(b, []byte("$1=$2"))), nil
}

func (r *Conf) providerConfigured(name string) bool {
	if name == r.DefaultProvider {
		return true
	}

	for _, rule := range r.Rules {
		if name == rule.Provider {
			return true
		}
	}

	return false
}

func (r *Conf) setupProvider(name string) error {
	p, err := r.GetProvider(name)
	if err != nil {
		return err
	}
	err = p.Setup()
	if err != nil {
		return err
	}
	return nil
}
