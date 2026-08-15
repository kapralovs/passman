package app

import (
	"github.com/kapralovs/passman/internal/config"
	"github.com/kapralovs/passman/internal/controllers"
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
	cryptoSvc usecase.CryptoUsecase,
) *App {
	sessionTTL := cfg.SessionDuration

	vaultRepo := repository.NewVaultRepository()
	sessionRepo := repository.NewSessionRepository(sessionPath)
	initUC := usecase.NewInitUsecase(configPath)
	signUpUC := usecase.NewSignUpUsecase(vaultRepo, sessionRepo)
	loginUC := usecase.NewLoginUsecase(vaultRepo, sessionRepo)
	addUC := usecase.NewAddPasswordUsecase(vaultRepo, cryptoSvc, sessionTTL)
	getUC := usecase.NewGetPasswordUsecase(vaultRepo, cryptoSvc, sessionTTL)

	controller := controllers.NewController(configPath, sessionRepo, initUC, signUpUC, loginUC, addUC, getUC)

	return &App{
		Controller: controller,
	}
}

// Run запускает приложение, обрабатывая аргументы командной строки.
func (a *App) Run(args []string) error {
	return a.Controller.Execute(args)
}
