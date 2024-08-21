package test

import (
	"io"
	"log"
	"os"
	"testing"

	"github.com/R00tendo/goauthy/pkg/constants"
	"github.com/R00tendo/goauthy/pkg/persistent"
)

func TestPersistentFeatures(t *testing.T) {
	//store := memory.Init()
	store, err := persistent.Init(nil, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	err = store.Add("user", "test", constants.USER)
	if err != nil {
		t.Fatal(err)
	}

	err = store.Add("@u ser", "test", constants.USER)
	if err == nil {
		t.Fatal("could make user with username containing illegal characters")
	}

	err = store.Add("user", "", constants.USER)
	if err == nil {
		t.Fatal("could make user with empty password")
	}

	user, err := store.Login("user", "test")
	if err != nil {
		t.Fatal(err)
	}

	err = user.ChangePassword("test1")
	if err != nil {
		t.Fatal(err)
	}

	if user.CheckAccess(constants.ADMIN) {
		t.Fatal("could use excessive rights")
	}

	user.LogOut()
	err = user.ChangePassword("test2")
	if err == nil {
		t.Fatal("could change password without valid session")
	}

	user, err = store.Login("user", "test1")
	if err != nil {
		t.Fatal(err)
	}

	user.Variables["test"] = "hello"

	user.LogOutFully()
	err = user.ChangePassword("test2")
	if err == nil {
		t.Fatal("could change password without valid session")
	}

	store2, err := persistent.Init(nil, nil, &persistent.UserSettings{AllowPasswordChange: false})
	if err != nil {
		t.Fatal(err)
	}
	err = store2.Add("test", "test", constants.PUBLIC)
	if err != nil {
		t.Fatal(err)
	}

	user, err = store2.Login("test", "test")
	if err != nil {
		t.Fatal(err)
	}

	err = user.ChangePassword("test2")
	if err == nil {
		t.Fatal("could change password even though password changing is disabled")
	}

	store.Close()
	store2.Close()

	err = os.Remove("goauthy.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
}
