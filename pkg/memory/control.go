package memory

import (
	"sync"

	"github.com/R00tendo/goauthy/internal/utils"
	"github.com/R00tendo/goauthy/pkg/constants"
)

type store struct { //Single source of truth
	lock     sync.Mutex
	users    map[string]*User
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
	return nil
}

func (store *store) remove(user *User) {
	store.lock.Lock()
	defer store.lock.Unlock()
	store.RemoveSessions(user.getSessions())
	for username := range store.users {
		if user.username == username {
			delete(store.users, username)
		}
	}
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
