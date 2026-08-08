package repository

import "github.com/kapralovs/passman/internal/session"

// SessionRepository — интерфейс для хранения состояния сессии.
type SessionRepository interface {
	Load() (*session.Session, error)
	Save(s *session.Session) error
}

// fileSessionRepository — файловая реализация SessionRepository.
type fileSessionRepository struct {
	filename string
}

// NewSessionRepository создаёт файловый репозиторий сессий.
func NewSessionRepository(filename string) SessionRepository {
	return &fileSessionRepository{filename: filename}
}

func (r *fileSessionRepository) Load() (*session.Session, error) {
	return session.Load(r.filename)
}

func (r *fileSessionRepository) Save(s *session.Session) error {
	return session.Save(r.filename, s)
}
