package controllers

import (
	"testing"

	"github.com/kapralovs/passman/internal/session"
	"github.com/stretchr/testify/assert"
)

func TestExtractFlagValue(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		flag     string
		expected string
	}{
		{
			name:     "flag present",
			args:     []string{"--service=gmail", "--login=user@gmail.com"},
			flag:     "--service",
			expected: "gmail",
		},
		{
			name:     "flag not present",
			args:     []string{"--login=user@gmail.com"},
			flag:     "--service",
			expected: "",
		},
		{
			name:     "empty args",
			args:     []string{},
			flag:     "--service",
			expected: "",
		},
		{
			name:     "flag with empty value",
			args:     []string{"--service=", "--login=user"},
			flag:     "--service",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractFlagValue(tt.args, tt.flag)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestController_ExecuteEmptyArgs(t *testing.T) {
	ctrl := &Controller{}
	err := ctrl.Execute([]string{})
	assert.Error(t, err)
	assert.Equal(t, "invalid command: (empty)", err.Error())
}

func TestController_ExecuteUnknownCommand(t *testing.T) {
	ctrl := &Controller{}
	err := ctrl.Execute([]string{"unknown"})
	assert.Error(t, err)
	assert.Equal(t, "invalid command: unknown", err.Error())
}

func TestController_ExecuteInit(t *testing.T) {
	mock := &mockInitUsecase{}
	ctrl := &Controller{
		InitUsecase: mock,
	}

	err := ctrl.Execute([]string{"init"})
	assert.NoError(t, err)
	assert.True(t, mock.called)
}

func TestController_ExecuteInitError(t *testing.T) {
	mock := &mockInitUsecase{err: assert.AnError}
	ctrl := &Controller{
		InitUsecase: mock,
	}

	err := ctrl.Execute([]string{"init"})
	assert.Error(t, err)
	assert.True(t, mock.called)
}

func TestController_ExecuteSignUp(t *testing.T) {
	mock := &mockSignUpUsecase{}
	ctrl := &Controller{
		SignUpUsecase: mock,
	}

	err := ctrl.Execute([]string{"signup", "--username=testuser"})
	assert.NoError(t, err)
	assert.True(t, mock.called)
	assert.Equal(t, "testuser", mock.username)
}

func TestController_ExecuteSignUpMissingUsername(t *testing.T) {
	mock := &mockSignUpUsecase{}
	ctrl := &Controller{
		SignUpUsecase: mock,
	}

	err := ctrl.Execute([]string{"signup"})
	assert.Error(t, err)
	assert.Equal(t, "--username is required for signup", err.Error())
	assert.False(t, mock.called)
}

func TestController_ExecuteLogin(t *testing.T) {
	mock := &mockLoginUsecase{}
	sessionRepo := &mockSessionRepo{}
	ctrl := &Controller{
		LoginUsecase: mock,
		SessionRepo:  sessionRepo,
	}

	err := ctrl.Execute([]string{"login"})
	assert.NoError(t, err)
	assert.True(t, mock.called)
}

func TestController_ExecuteLoginError(t *testing.T) {
	mock := &mockLoginUsecase{err: assert.AnError}
	sessionRepo := &mockSessionRepo{}
	ctrl := &Controller{
		LoginUsecase: mock,
		SessionRepo:  sessionRepo,
	}

	err := ctrl.Execute([]string{"login"})
	assert.Error(t, err)
	assert.True(t, mock.called)
}

func TestController_ExecuteAdd(t *testing.T) {
	mock := &mockAddUsecase{}
	sessionRepo := &mockSessionRepo{
		sess: &session.Session{Username: "testuser"},
	}
	ctrl := &Controller{
		AddUsecase: mock,
		SessionRepo: sessionRepo,
	}

	err := ctrl.Execute([]string{
		"add",
		"--service=gmail",
		"--login=user@gmail.com",
		"--password=secret",
	})
	assert.NoError(t, err)
	assert.True(t, mock.called)
}

func TestController_ExecuteAddMissingArgs(t *testing.T) {
	mock := &mockAddUsecase{}
	ctrl := &Controller{
		AddUsecase: mock,
	}

	err := ctrl.Execute([]string{"add", "--service=gmail"})
	assert.Error(t, err)
	assert.False(t, mock.called)
}

func TestController_ExecuteGet(t *testing.T) {
	mock := &mockGetUsecase{password: "secret123"}
	sessionRepo := &mockSessionRepo{
		sess: &session.Session{Username: "testuser"},
	}
	ctrl := &Controller{
		GetUsecase: mock,
		SessionRepo: sessionRepo,
	}

	err := ctrl.Execute([]string{"get", "--service=gmail"})
	assert.NoError(t, err)
	assert.True(t, mock.called)
}

func TestController_ExecuteGetMissingService(t *testing.T) {
	mock := &mockGetUsecase{}
	ctrl := &Controller{
		GetUsecase: mock,
	}

	err := ctrl.Execute([]string{"get"})
	assert.Error(t, err)
	assert.Equal(t, "--service is required for get", err.Error())
	assert.False(t, mock.called)
}
