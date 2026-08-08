package controllers

import (
	"errors"
	"fmt"
	"os"

	"github.com/kapralovs/passman/internal/repository"
	"github.com/kapralovs/passman/internal/usecase"
)

// Controller обрабатывает команды CLI и вызывает соответствующие use cases.
type Controller struct {
	ConfigPath     string
	SessionRepo    repository.SessionRepository
	InitUsecase    *usecase.InitUsecase
	SignUpUsecase  *usecase.SignUpUsecase
	LoginUsecase   *usecase.LoginUsecase
	AddUsecase     *usecase.AddPasswordUsecase
	GetUsecase     *usecase.GetPasswordUsecase
}

// NewController создаёт контроллер с инициализированными use cases.
func NewController(
	configPath string,
	sessionRepo repository.SessionRepository,
	init *usecase.InitUsecase,
	signUp *usecase.SignUpUsecase,
	login *usecase.LoginUsecase,
	add *usecase.AddPasswordUsecase,
	get *usecase.GetPasswordUsecase,
) *Controller {
	return &Controller{
		ConfigPath:    configPath,
		SessionRepo:   sessionRepo,
		InitUsecase:   init,
		SignUpUsecase: signUp,
		LoginUsecase:  login,
		AddUsecase:    add,
		GetUsecase:    get,
	}
}

// Execute выполняет команду, переданную через os.Args[1:].
func (c *Controller) Execute(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("invalid command: (empty)")
	}

	switch args[0] {
	case "init":
		return c.InitUsecase.Execute()
	case "signup":
		return c.handleSignUp(args[1:])
	case "login":
		return c.handleLogin(args[1:])
	case "add":
		return c.handleAdd(args[1:])
	case "get":
		return c.handleGet(args[1:])
	default:
		return fmt.Errorf("invalid command: %s", args[0])
	}
}

func (c *Controller) handleSignUp(args []string) error {
	username := extractFlagValue(args, "--username")
	if username == "" {
		return errors.New("--username is required for signup")
	}

	return c.SignUpUsecase.Execute(username)
}

func (c *Controller) handleLogin(args []string) error {
	sess, err := c.SessionRepo.Load()
	if err != nil {
		return err
	}

	_, err = c.LoginUsecase.Execute(sess)
	if err != nil {
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

	_, userData, err := c.AddUsecase.Execute(sess, service, login, password)
	if err != nil {
		return err
	}

	vaultRepo := repository.NewVaultRepository()
	if err := vaultRepo.Write(sess.Username, userData); err != nil {
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

	password, err := c.GetUsecase.Execute(sess, service)
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