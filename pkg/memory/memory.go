package memory

import (
	"log"
	"regexp"
	"sync"

	"github.com/R00tendo/goauthy/internal/utils"
	"github.com/R00tendo/goauthy/pkg/constants"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Options struct {
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
func Init(userOptions ...any) *store {
	defaultOptions := []any{
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
		logger:        defaultOptions[0].(*log.Logger),
		UserSettings:  defaultOptions[1].(*UserSettings),
		usernameRegex: defaultOptions[2].(*regexp.Regexp),
		passRegex:     defaultOptions[3].(*regexp.Regexp),
	}
	newStore := &store{
		lock:     sync.Mutex{},
		options:  options,
		users:    make(map[string]*User),
		sessions: make(map[string]*User),
	}
	return newStore
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

type RestSettings struct {
	Listener string
	Store    *store
	Debug    bool
	Logger   *log.Logger
}

// Rest api args(memory.RestSettings)
func StartRest(settings *RestSettings) error {
	app := fiber.New(fiber.Config{ServerHeader: "GoAuthy"})

	app.Post("/add", func(c *fiber.Ctx) error {
		errHandle := func(err error) {
			if settings.Debug {
				settings.Logger.Println(err.Error())
				c.Status(500).Send([]byte(err.Error()))
			} else {
				c.Send([]byte(""))
			}
		}

		payload := &struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Access   int    `json:"access"`
		}{}
		err := c.BodyParser(payload)
		if err != nil {
			errHandle(err)
			return err
		}

		err = settings.Store.Add(payload.Username, payload.Password, payload.Access)
		if err != nil {
			errHandle(err)
			return err
		}

		return c.JSON(map[string]string{
			"status": "success",
		})
	})

	app.Post("/delete", func(c *fiber.Ctx) error {
		errHandle := func(err error) {
			if settings.Debug {
				settings.Logger.Println(err.Error())
				c.Status(500).Send([]byte(err.Error()))
			} else {
				c.Send([]byte(""))
			}
		}

		payload := &struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}{}
		err := c.BodyParser(payload)
		if err != nil {
			errHandle(err)
			return err
		}
		user, err := settings.Store.Login(payload.Username, payload.Password)
		if err != nil {
			errHandle(err)
			return err
		}
		user.Delete()

		return c.JSON(map[string]string{
			"status": "success",
		})
	})

	app.Post("/login", func(c *fiber.Ctx) error {
		errHandle := func(err error) {
			if settings.Debug {
				settings.Logger.Println(err.Error())
				c.Status(500).Send([]byte(err.Error()))
			} else {
				c.Send([]byte(""))
			}
		}

		payload := &struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}{}
		err := c.BodyParser(payload)
		if err != nil {
			errHandle(err)
			return err
		}
		user, err := settings.Store.Login(payload.Username, payload.Password)
		if err != nil {
			return c.Status(401).JSON(map[string]string{
				"status": "invalid credentials",
			})
		}
		user.LogOut()

		return c.JSON(map[string]string{
			"status": "success",
		})
	})

	return app.Listen(settings.Listener)
}
