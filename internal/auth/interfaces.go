package internal

import (
	"github.com/kapralovs/passman/internal/models/account"
	"github.com/kapralovs/passman/internal/models/auth"
)

type Repo interface {
	Add(p *account.AccountInfo) error
	Delete(id int64) error
	Get(id int64) (*account.AccountInfo, error)
}

type Usecase interface {
	Add(p *account.AccountInfo) error
	Delete(id int64) error
	Get(id int64) (*account.AccountInfo, error)
	SignUp(login, password string) (auth.Token, error)
	SignIn(token string) (auth.Token, error)
}
