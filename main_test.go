package main

import (
	"github.com/DATA-DOG/go-sqlmock"
	"testing"
)

func TestGenerateRandomNumber(t *testing.T) {
	min := 100000
	max := 999999
	result := generateRandomNumber(min, max)

	if result < min || result > max {
		t.Errorf("generateRandomNumber() = %d; want value between %d and %d", result, min, max)
	}
}

// Предполагается использование пакета sqlmock для мокирования SQL-запросов
func TestIsValidLogin(t *testing.T) {
	// Создание мок-объекта базы данных
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	username, password := "testUser", "testPass"
	rows := sqlmock.NewRows([]string{"password"}).AddRow(password)

	mock.ExpectQuery("SELECT password FROM users WHERE username = \\$1").
		WithArgs(username).
		WillReturnRows(rows)

	// Передача объекта базы данных в функцию isValidLogin
	if !isValidLogin(db, username, password) {
		t.Errorf("Expected valid login to be true for username %s", username)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("There were unfulfilled expectations: %s", err)
	}
}
