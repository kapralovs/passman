package commands

import (
	"flag"
	"fmt"

	"github.com/kapralovs/passman/internal/config"
	"github.com/kapralovs/passman/internal/crypto"
	"github.com/kapralovs/passman/internal/session"
	"github.com/kapralovs/passman/internal/storage"
)

type Context struct {
	Config  *config.Manager
	Storage *storage.Service
	Crypto  *crypto.Service
	Session *session.Manager
}

func NewContext() (*Context, error) {
	cfgMgr := config.New()
	if err := cfgMgr.Load(); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return &Context{
		Config:  cfgMgr,
		Storage: storage.New(),
		Crypto:  crypto.New(),
		Session: mustCreateSession(),
	}, nil
}

func mustCreateSession() *session.Manager {
	sess, _ := session.New() // Ignoring error for simplicity
	return sess
}

type Command interface {
	Name() string
	Execute(args []string) error
}

func parseStringFlag(flagSet *flag.FlagSet, name, description string) *string {
	return flagSet.String(name, "", description)
}

func getFlagValue(flag *string) string {
	if flag != nil {
		return *flag
	}
	return ""
}
