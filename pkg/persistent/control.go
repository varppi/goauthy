package persistent

import (
	"database/sql"
	"sync"

	"github.com/R00tendo/goauthy/internal/utils"
	"github.com/R00tendo/goauthy/pkg/constants"
	_ "github.com/mattn/go-sqlite3"
)

type store struct {
	users    map[string]*User
	lock     sync.Mutex
	database *sql.DB
	sessions map[string]*User
	options  *Options
}

func (store *store) get(username string) (*User, error) {
	store.lock.Lock()
	defer store.lock.Unlock()
	for _, user := range store.users {
		if user.username == username {
			return user, nil
		}
	}
	return &User{}, constants.ErrNotFound
}

func (store *store) add(user *User) error {
	store.lock.Lock()
	defer store.lock.Unlock()
	for username := range store.users {
		if user.username == username {
			return constants.ErrAlreadyExists
		}
	}
	passHash, err := utils.HashPassword(user.password)
	if err != nil {
		return err
	}
	user.password = passHash
	store.users[user.username] = user
	statement, err := store.database.Prepare(`INSERT INTO users(username, password, access) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	_, err = statement.Exec(user.username, user.password, user.access)
	if err != nil {
		return err
	}
	return nil
}

func (store *store) remove(user *User) error {
	store.lock.Lock()
	defer store.lock.Unlock()
	statement, err := store.database.Prepare(`DELETE FROM users WHERE username=?`)
	if err != nil {
		return err
	}
	_, err = statement.Exec(user.username)
	if err != nil {
		return err
	}
	store.RemoveSessions(user.getSessions())
	for username := range store.users {
		if user.username == username {
			delete(store.users, username)
		}
	}
	return nil
}

func (store *store) newSession(session string, user *User) error {
	store.lock.Lock()
	defer store.lock.Unlock()
	if _, ok := store.sessions[session]; ok {
		return constants.ErrAlreadyAuthenticated
	}
	store.sessions[session] = user
	return nil
}

func (store *store) rawAdd(user *User) error {
	store.lock.Lock()
	defer store.lock.Unlock()
	for username := range store.users {
		if user.username == username {
			return constants.ErrAlreadyExists
		}
	}
	store.users[user.username] = user
	return nil
}

func (store *store) close() error {
	return store.database.Close()
}
