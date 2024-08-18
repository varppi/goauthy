package constants

import (
	"errors"
)

const DELETED = -2
const PUBLIC = -1
const ADMIN = 0
const USER = 1

var ErrInvalidUsernamePassword = errors.New("the username or password is empty or contained characters that are not allowed")
var ErrNotFound = errors.New("not found")
var ErrAlreadyExists = errors.New("user already exists")
var ErrNotAllowed = errors.New("this action is not permitted")
var ErrAlreadyAuthenticated = errors.New("user already signed in, multiple session disabled")
