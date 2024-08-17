package repo

import (
	"simple_jwt_based_auth/models"
)

var Users = map[string]models.User{
	"user1": {ID: 1, Username: "user1", Password: "pass1"},
	"user2": {ID: 2, Username: "user2", Password: "pass2"},
}

func GetUser(username string) (models.User, bool) {
	user, exists := Users[username]
	return user, exists
}

// Лишь для примера(поэтому не в моделях)
var Items = map[string]string{
	"item1": "A table",
	"item2": "A lamp",
	"item3": "A phone",
	"item4": "A TV set",
	"item5": "A teapot",
}

func GetAllItems() []string {
	values := []string{}
	for _, value := range Items {
		values = append(values, value)
	}
	return values
}
