package internal

import (
	"github.com/kapralovs/passman/internal/models/account"
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
}
