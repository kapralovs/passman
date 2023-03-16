type Repo interface {
	Add(p *models.PasswordInfo) error
	Delete(id int64) error
	Get(id int64) (*models.PasswordInfo, error)
}

type Usecase interface {
	Add(p *models.PasswordInfo) error
	Delete(id int64) error
	Get(id int64) (*models.PasswordInfo, error)
	SignUp(login, password string) (models.Token, error)
}
