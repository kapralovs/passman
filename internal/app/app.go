package app

import (
	"time"

	"github.com/kapralovs/passman/internal/controllers"
	"github.com/kapralovs/passman/internal/repository"
	"github.com/kapralovs/passman/internal/usecase"
)

// App содержит все зависимости и точку запуска приложения.
type App struct {
	Controller *controllers.Controller
}

// New создаёт приложение с инициализированными use cases и контроллером.
func New(cfgRepo repository.ConfigRepository, vaultRepo repository.VaultRepository, crypto usecase.CryptoUsecase) *App {
	sessionTTL := 30 * time.Second

	initUC := usecase.NewInitUsecase(cfgRepo)
	signUpUC := usecase.NewSignUpUsecase(cfgRepo, vaultRepo)
	loginUC := usecase.NewLoginUsecase(cfgRepo, vaultRepo)
	addUC := usecase.NewAddPasswordUsecase(cfgRepo, vaultRepo, crypto, sessionTTL)
	getUC := usecase.NewGetPasswordUsecase(cfgRepo, vaultRepo, crypto, sessionTTL)

	controller := controllers.NewController(initUC, signUpUC, loginUC, addUC, getUC)

	return &App{Controller: controller}
}

// Run запускает приложение, обрабатывая аргументы командной строки.
func (a *App) Run(args []string) error {
	return a.Controller.Execute(args)
}
