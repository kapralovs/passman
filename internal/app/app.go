package app

import (
	"time"

	"github.com/kapralovs/passman/internal/config"
	"github.com/kapralovs/passman/internal/controllers"
	"github.com/kapralovs/passman/internal/repository"
	"github.com/kapralovs/passman/internal/usecase"
)

// App содержит все зависимости и точку запуска приложения.
type App struct {
	Controller *controllers.Controller
	ConfigPath string
}

// New создаёт приложение с инициализированными use cases и контроллером.
func New(configPath string, vaultRepo repository.VaultRepository, cryptoSvc usecase.CryptoUsecase) *App {
	sessionTTL := 30 * time.Second

	initUC := usecase.NewInitUsecase(configPath)
	signUpUC := usecase.NewSignUpUsecase(vaultRepo)
	loginUC := usecase.NewLoginUsecase(vaultRepo)
	addUC := usecase.NewAddPasswordUsecase(vaultRepo, cryptoSvc, sessionTTL)
	getUC := usecase.NewGetPasswordUsecase(vaultRepo, cryptoSvc, sessionTTL)

	controller := controllers.NewController(configPath, initUC, signUpUC, loginUC, addUC, getUC)

	return &App{
		Controller: controller,
		ConfigPath: configPath,
	}
}

// Run запускает приложение, обрабатывая аргументы командной строки.
func (a *App) Run(args []string) error {
	return a.Controller.Execute(args)
}

// LoadConfig загружает конфигурацию из файла.
func (a *App) LoadConfig() (*config.Config, error) {
	return config.Load(a.ConfigPath)
}

// SaveConfig сохраняет конфигурацию в файл.
func (a *App) SaveConfig(cfg *config.Config) error {
	return config.Save(a.ConfigPath, cfg)
}
