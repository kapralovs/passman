package controllers

import (
	"github.com/kapralovs/passman/internal/entities"
	"github.com/kapralovs/passman/internal/session"
)

// mockSessionRepo implements repository.SessionRepository
type mockSessionRepo struct {
	sess *session.Session
	err  error
}

func (m *mockSessionRepo) Load() (*session.Session, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.sess == nil {
		return &session.Session{}, nil
	}
	return m.sess, nil
}

func (m *mockSessionRepo) Save(s *session.Session) error {
	if m.err != nil {
		return m.err
	}
	m.sess = s
	return nil
}

// mockInitUsecase implements InitUsecase
type mockInitUsecase struct {
	called bool
	err    error
}

func (m *mockInitUsecase) Execute() error {
	m.called = true
	return m.err
}

// mockSignUpUsecase implements SignUpUsecase
type mockSignUpUsecase struct {
	called   bool
	username string
	err      error
}

func (m *mockSignUpUsecase) Execute(username string) error {
	m.called = true
	m.username = username
	return m.err
}

// mockLoginUsecase implements LoginUsecase
type mockLoginUsecase struct {
	called bool
	err    error
}

func (m *mockLoginUsecase) Execute(sess *session.Session) (*session.Session, error) {
	m.called = true
	return sess, m.err
}

// mockAddUsecase implements AddPasswordUsecase
type mockAddUsecase struct {
	called bool
	err    error
}

func (m *mockAddUsecase) Execute(sess *session.Session, service, login, password string) (*session.Session, *entities.UserData, error) {
	m.called = true
	return sess, &entities.UserData{}, m.err
}

// mockGetUsecase implements GetPasswordUsecase
type mockGetUsecase struct {
	called   bool
	password string
	err      error
}

func (m *mockGetUsecase) Execute(sess *session.Session, service string) (string, error) {
	m.called = true
	return m.password, m.err
}
