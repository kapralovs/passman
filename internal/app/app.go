package app

import (
	"fmt"

	"github.com/kapralovs/passman/internal/config"
	"github.com/kapralovs/passman/internal/controllers"
	"github.com/kapralovs/passman/internal/crypto"
	"github.com/kapralovs/passman/internal/repository"
	"github.com/kapralovs/passman/internal/usecase"
)

// App содержит все зависимости и точку запуска приложения.
type App struct {
	Controller *controllers.Controller
}

// New создаёт приложение с инициализированными use cases и контроллером.
func New(
	configPath string,
	cfg *config.Config,
	sessionPath string,
) (*App, error) {
	sessionTTL := cfg.SessionDuration

	vaultRepo := repository.NewVaultRepository()
	sessionRepo := repository.NewSessionRepository(sessionPath)

	initUC := usecase.NewInitUsecase(configPath)
	signUpUC := usecase.NewSignUpUsecase(vaultRepo, sessionRepo)
	loginUC := usecase.NewLoginUsecase(vaultRepo, sessionRepo)

	cryptoSvc, err := crypto.NewAESCrypto(cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("set crypto usecase")
	}

	addUC := usecase.NewAddPasswordUsecase(vaultRepo, cryptoSvc, sessionTTL)
	getUC := usecase.NewGetPasswordUsecase(vaultRepo, cryptoSvc, sessionTTL)

	controller := controllers.NewController(configPath, sessionRepo, initUC, signUpUC, loginUC, addUC, getUC)

	a := &App{
		Controller: controller,
	}

	return a, nil
}

// Run запускает приложение, обрабатывая аргументы командной строки.
func (a *App) Run(args []string) error {
	return a.Controller.Execute(args)
}
