package persistent

import (
	"log"
	"regexp"
	"sync"

	"database/sql"

	"github.com/R00tendo/goauthy/internal/utils"
	"github.com/R00tendo/goauthy/pkg/constants"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type Options struct {
	database      string
	usernameRegex *regexp.Regexp
	passRegex     *regexp.Regexp
	logger        *log.Logger
	UserSettings  *UserSettings
}

type User struct {
	Variables map[string]any
	username  string
	access    int
	password  string
	store     *store
	session   string
}

type UserSettings struct {
	MaxSessions         int  //  0 = infinite  default:0
	AllowPasswordChange bool //                default:true
}

// Initializes store Init(logger*, UserSettings*, usernameRegex*, passRegex*)
func Init(userOptions ...any) (*store, error) {
	defaultOptions := []any{
		"goauthy.sqlite3",
		log.Default(),
		&UserSettings{0, true},
		regexp.MustCompile(`^[a-zA-Z0-9+\.+_]+$`),
		regexp.MustCompile(`.+`),
	}
	for index, option := range userOptions {
		if option != nil && index < len(defaultOptions) {
			defaultOptions[index] = option
		}
	}
	options := &Options{
		database:      defaultOptions[0].(string),
		logger:        defaultOptions[1].(*log.Logger),
		UserSettings:  defaultOptions[2].(*UserSettings),
		usernameRegex: defaultOptions[3].(*regexp.Regexp),
		passRegex:     defaultOptions[4].(*regexp.Regexp),
	}
	database, err := sql.Open("sqlite3", options.database)
	if err != nil {
		return &store{}, err
	}
	_, err = database.Exec("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, access INTEGER)")
	if err != nil {
		return &store{}, err
	}
	newStore := &store{
		users:    make(map[string]*User),
		lock:     sync.Mutex{},
		options:  options,
		database: database,
		sessions: make(map[string]*User),
	}
	users, err := database.Query(`SELECT * FROM users`)
	if err != nil {
		return &store{}, err
	}
	for users.Next() {
		var username, password string
		var access int
		err := users.Scan(&username, &password, &access)
		if err != nil {
			return &store{}, err
		}
		newStore.rawAdd(&User{
			username:  username,
			password:  password,
			access:    access,
			store:     newStore,
			Variables: make(map[string]any),
		})
	}
	return newStore, nil
}

// Adds new user Add(username, password, access level)
func (store *store) Add(username, password string, access int) error {
	user := &User{
		username:  username,
		password:  password,
		access:    access,
		Variables: make(map[string]any),
	}
	if !store.options.usernameRegex.Match([]byte(user.username)) || !store.options.passRegex.Match([]byte(user.password)) {
		return constants.ErrInvalidUsernamePassword
	}
	err := store.add(user)
	if err != nil {
		store.options.logger.Println("Add(): " + err.Error())
	}
	user.store = store
	return nil
}

// Gets the user object from username
func (store *store) UserFromUsername(username string) (*User, error) {
	user, err := store.get(username)
	if err != nil {
		store.options.logger.Println("Get(): " + err.Error())
	}
	return user, err
}

// Gets the user object from session id
func (store *store) UserFromID(sessionID string) (*User, error) {
	for session, user := range store.sessions {
		if session == sessionID {
			return user, nil
		}
	}
	return &User{}, constants.ErrNotFound
}

// Returns the user's username
func (user *User) Username() string {
	return user.username
}

// Returns the user's current session id
func (user *User) Session() string {
	if !user.validateSession() {
		user.session = ""
	}
	return user.session
}

// Resets user passsword
func (user *User) ChangePassword(password string) error {
	if !user.validateSession() {
		return constants.ErrNotAllowed
	}
	if !user.store.options.usernameRegex.Match([]byte(user.username)) || !user.store.options.passRegex.Match([]byte(password)) {
		return constants.ErrInvalidUsernamePassword
	}
	if !user.store.options.UserSettings.AllowPasswordChange {
		return constants.ErrNotAllowed
	}
	hashPass, err := utils.HashPassword(password)
	if err != nil {
		return err
	}
	statement, err := user.store.database.Prepare(`UPDATE users SET password=? WHERE username=?`)
	if err != nil {
		return err
	}
	_, err = statement.Exec(user.password, user.username)
	if err != nil {
		return err
	}
	user.password = hashPass
	return nil
}

// Deletes the user's current session
func (user *User) LogOut() {
	user.store.RemoveSessions([]string{user.session})
}

// Deletes all user sessions
func (user *User) LogOutFully() {
	user.store.RemoveSessions(user.getSessions())
}

// Deletes the user
func (user *User) Delete() {
	user.store.remove(user)
	user.password = ""
	user.username = ""
	user.session = ""
	user.access = -1
	user.Variables = nil
}

// Revokes the given sessions RemoveSessions([]string{"session id", "session id 2"})
func (store *store) RemoveSessions(sessions []string) {
	for _, session := range sessions {
		delete(store.sessions, session)
	}
}

/*
Attempts to login with given credentials and returns user object containing a valid session if successful
Login(username, password, session id*)
*/
func (store *store) Login(username, password string, sessionID ...string) (*User, error) {
	if !store.options.usernameRegex.Match([]byte(username)) || !store.options.passRegex.Match([]byte(password)) {
		return &User{}, constants.ErrInvalidUsernamePassword
	}
	user, err := store.UserFromUsername(username)
	if err != nil {
		return &User{}, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.password), []byte(password))
	if err != nil {
		return &User{}, err
	}
	if store.options.UserSettings.MaxSessions == len(user.getSessions()) && store.options.UserSettings.MaxSessions > 0 {
		return &User{}, constants.ErrAlreadyAuthenticated
	}
	_sessionID := uuid.NewString()
	if len(sessionID) == 1 {
		_sessionID = sessionID[0]
	}
	user.session = _sessionID
	err = store.newSession(user.session, user)
	if err != nil {
		return &User{}, err
	}
	return user, nil
}

// Checks whether user has X level of access
func (user *User) CheckAccess(accessLevel int) bool {
	if user.access == -2 {
		return false
	}
	if accessLevel == -1 {
		return true
	}
	if (user.access > accessLevel) || !user.validateSession() {
		return false
	} else {
		return true
	}
}

// Changes access level to the desired one
func (user *User) ChangeAccess(accessLevel int) {
	user.access = accessLevel
}

// Returns all the user's sessions
func (user *User) getSessions() []string {
	var sessions []string
	for session, storeUser := range user.store.sessions {
		if storeUser.username == user.username {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// Validates that the session is valid
func (user *User) validateSession() bool {
	sessionToValidate := user.session
	for _, session := range user.getSessions() {
		if session == sessionToValidate {
			fromSessionUser, err := user.store.UserFromID(session)
			if err != nil || user != fromSessionUser {
				return false
			}
			return true
		}
	}
	return false
}

func (store *store) Close() error {
	err := store.close()
	if err != nil {
		return err
	}
	store = nil
	return nil
}
