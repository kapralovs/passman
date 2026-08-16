package controllers

import (
	"errors"
	"fmt"
	"os"

	"github.com/kapralovs/passman/internal/repository"
	"github.com/kapralovs/passman/internal/usecase"
)

// UseCases содержит все use cases для контроллера.
type UseCases struct {
	Init         *usecase.InitUsecase
	SignUp       *usecase.SignUpUsecase
	Login        *usecase.LoginUsecase
	Add          *usecase.AddPasswordUsecase
	Update       *usecase.UpdateServicePasswordUsecase
	Get          *usecase.GetPasswordUsecase
}

// Controller обрабатывает команды CLI и вызывает соответствующие use cases.
type Controller struct {
	ConfigPath  string
	SessionRepo repository.SessionRepository
	UseCases    UseCases
}

// NewController создаёт контроллер с инициализированными use cases.
func NewController(
	configPath string,
	sessionRepo repository.SessionRepository,
	useCases UseCases,
) *Controller {
	return &Controller{
		ConfigPath:  configPath,
		SessionRepo: sessionRepo,
		UseCases:    useCases,
	}
}

// Execute выполняет команду, переданную через os.Args[1:].
func (c *Controller) Execute(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("invalid command: (empty)")
	}

	switch args[0] {
	case "init":
		return c.UseCases.Init.Execute()
	case "signup":
		return c.handleSignUp(args[1:])
	case "login":
		return c.handleLogin(args[1:])
	case "add":
		return c.handleAdd(args[1:])
	case "update":
		return c.handleUpdate(args[1:])
	case "get":
		return c.handleGet(args[1:])
	case "help":
		c.printHelp()
		return nil
	default:
		return fmt.Errorf("invalid command: %s", args[0])
	}
}

func (c *Controller) handleSignUp(args []string) error {
	username := extractFlagValue(args, "--username")
	if username == "" {
		return errors.New("--username is required for signup")
	}

	return c.UseCases.SignUp.Execute(username)
}

func (c *Controller) handleLogin(args []string) error {
	sess, err := c.SessionRepo.Load()
	if err != nil {
		return err
	}

	if _, err = c.UseCases.Login.Execute(sess); err != nil {
		return err
	}

	return c.SessionRepo.Save(sess)
}

func (c *Controller) handleAdd(args []string) error {
	service := extractFlagValue(args, "--service")
	login := extractFlagValue(args, "--login")
	password := extractFlagValue(args, "--password")

	if service == "" || login == "" || password == "" {
		return errors.New("--service, --login, and --password are required for add")
	}

	sess, err := c.SessionRepo.Load()
	if err != nil {
		return err
	}

	_, userData, err := c.UseCases.Add.Execute(sess, service, login, password)
	if err != nil {
		return err
	}

	vaultRepo := repository.NewVaultRepository()
	if err = vaultRepo.Write(sess.Username, userData); err != nil {
		return err
	}

	return c.SessionRepo.Save(sess)
}

func (c *Controller) handleUpdate(args []string) error {
	service := extractFlagValue(args, "--service")
	login := extractFlagValue(args, "--login")
	password := extractFlagValue(args, "--password")

	if service == "" || login == "" || password == "" {
		return errors.New("--service, --login, and --password are required for update")
	}

	sess, err := c.SessionRepo.Load()
	if err != nil {
		return err
	}

	userData, err := c.UseCases.Update.Execute(sess, service, login, password)
	if err != nil {
		return err
	}

	vaultRepo := repository.NewVaultRepository()
	if err = vaultRepo.Write(sess.Username, userData); err != nil {
		return err
	}

	return c.SessionRepo.Save(sess)
}

func (c *Controller) handleGet(args []string) error {
	service := extractFlagValue(args, "--service")
	if service == "" {
		return errors.New("--service is required for get")
	}

	sess, err := c.SessionRepo.Load()
	if err != nil {
		return err
	}

	password, err := c.UseCases.Get.Execute(sess, service)
	if err != nil {
		return err
	}

	fmt.Fprint(os.Stdout, password)
	return nil
}

func extractFlagValue(args []string, flag string) string {
	for _, arg := range args {
		if len(arg) >= len(flag)+1 && arg[:len(flag)] == flag {
			return arg[len(flag)+1:]
		}
	}

	return ""
}

// printHelp выводит справку по командам.
func (c *Controller) printHelp() {
	fmt.Println("Passman — менеджер паролей")
	fmt.Println()
	fmt.Println("Доступные команды:")
	fmt.Println("  init                  Инициализировать конфигурацию")
	fmt.Println("  signup --username=U   Зарегистрировать нового пользователя")
	fmt.Println("  login                 Войти в систему")
	fmt.Println("  add --service=S --login=L --password=P")
	fmt.Println("                        Добавить пароль для сервиса")
	fmt.Println("  update --service=S --login=L --password=P")
	fmt.Println("                        Обновить пароль для сервиса")
	fmt.Println("  get --service=S       Получить пароль для сервиса")
	fmt.Println("  help                  Показать эту справку")
}
