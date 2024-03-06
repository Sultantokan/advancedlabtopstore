package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	//"text/template"

	"html/template"
	"math/rand"
	"net/smtp"
	"time"
	"io/ioutil"

	_ "github.com/lib/pq"
)

// Session хранит данные пользователя в течение сеанса регистрации
type Session struct {
	Username         string
	Email            string
	Password         string
	VerificationCode int
	Role             string
}

// User представляет данные пользователя
type User struct {
	ID       int
	Username string
	Email    string
	Password string
	Role     string
	// Другие поля пользователя, если они есть
}

var Sessions = make(map[string]Session)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "admin"
	dbname   = "postgres"
)

var db *sql.DB

func main() {
	// Установка соединения с базой данных
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		// Извлекаем сессию пользователя
		session, ok := Sessions[r.RemoteAddr]
		if !ok {
			// Если сессия не найдена, перенаправляем на страницу входа
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Проверяем, что роль пользователя - user
		if session.Role != "admin" {
			// Если роль не user, возвращаем ошибку 403 Forbidden
			http.Error(w, "Forbidden: Access is allowed only for users.", http.StatusForbidden)
			return
		}

		// Ваш код для обработки запроса к админ панели...

		brandFilter := r.URL.Query().Get("brandFilter")
		sortOrder := r.URL.Query().Get("sortOrder")

		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil || page < 1 {
			page = 1
		}
		perPage := 20
		offset := (page - 1) * perPage

		var queryBuilder strings.Builder
		queryBuilder.WriteString("SELECT * FROM laptop")

		if brandFilter != "" {
			queryBuilder.WriteString(fmt.Sprintf(" WHERE brand = '%s'", brandFilter))
		}

		if sortOrder != "" {
			queryBuilder.WriteString(fmt.Sprintf(" ORDER BY %s", sortOrder))
		}

		queryBuilder.WriteString(fmt.Sprintf(" LIMIT %d OFFSET %d", perPage, offset))

		rows, err := db.Query(queryBuilder.String())
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var laptops []Laptop
		for rows.Next() {
			var laptop Laptop
			err := rows.Scan(&laptop.ID, &laptop.Brand, &laptop.Model, &laptop.Processor, &laptop.GPU, &laptop.RAM, &laptop.StorageCapacity, &laptop.ScreenSize, &laptop.Price)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			laptops = append(laptops, laptop)
		}

		// Подготовка и отображение админ панели
		tmpl, err := template.ParseFiles("index.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, laptops)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/main", func(w http.ResponseWriter, r *http.Request) {
		// Открываем соединение с базой данных
		// Предполагается, что db уже инициализирован

		// Обновленный SQL-запрос для получения всех необходимых данных
		rows, err := db.Query("SELECT id, brand, model, processor, gpu, ram, storage_capacity, screen_size, price FROM laptop")
		if err != nil {

			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var laptops []Laptop // Убедитесь, что структура Laptop содержит все поля, которые вы извлекаете

		// Итерация по результатам запроса
		for rows.Next() {
			var laptop Laptop
			// Убедитесь, что порядок и количество полей здесь соответствует вашему запросу SELECT
			if err := rows.Scan(&laptop.ID, &laptop.Brand, &laptop.Model, &laptop.Processor, &laptop.GPU, &laptop.RAM, &laptop.StorageCapacity, &laptop.ScreenSize, &laptop.Price); err != nil {

				continue // или обработайте ошибку более жестко
			}
			laptops = append(laptops, laptop)
		}

		// Парсинг шаблона и передача данных в шаблон
		tmpl, err := template.ParseFiles("mainPage.html")
		if err != nil {

			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, laptops)
		if err != nil {

			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		// Получаем сессию пользователя по его IP-адресу
		session, ok := Sessions[r.RemoteAddr]
		if !ok {
			// Если сессия не найдена, перенаправляем на страницу входа
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Парсинг шаблона и передача данных сессии в шаблон
		tmpl, err := template.ParseFiles("profile.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, session)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		// Здесь удаляем данные сессии пользователя
		userIP := r.RemoteAddr // Используйте IP-адрес пользователя как ключ
		if _, ok := Sessions[userIP]; ok {
			_, err := db.Exec("DELETE FROM laptop_cart")
			if err != nil {
				// Обработка ошибки, если запрос на удаление не выполнен
				http.Error(w, "Error clearing cart", http.StatusInternalServerError)
				return
			}
			delete(Sessions, userIP) // Удаление сессии пользователя
		}

		// После удаления сессии перенаправляем пользователя на страницу входа или на главную страницу
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	http.HandleFunc("/updateLaptop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Unsupported request method.", http.StatusMethodNotAllowed)
			return
		}

		// Парсим данные из формы
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}

		id, err := strconv.Atoi(r.FormValue("id"))
		if err != nil {
			http.Error(w, "Invalid ID", http.StatusBadRequest)
			return
		}

		// Получаем остальные данные из формы
		ram, _ := strconv.Atoi(r.FormValue("ram"))
		storageCapacity, _ := strconv.Atoi(r.FormValue("storageCapacity"))
		screenSize, _ := strconv.ParseFloat(r.FormValue("screenSize"), 64)
		price, _ := strconv.Atoi(r.FormValue("price"))

		// Здесь логика обновления данных в базе
		_, err = db.Exec("UPDATE laptop SET ram = $1, storage_capacity = $2, screen_size = $3, price = $4  WHERE id = $5", ram, storageCapacity, screenSize, price, id)
		if err != nil {
			http.Error(w, "Error updating database", http.StatusInternalServerError)
			return
		}

		// Перенаправление на главную страницу после обновления
		http.Redirect(w, r, "admin?brandFilter=&sortOrder=id", http.StatusSeeOther)
	})

	http.HandleFunc("/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}

		// Считывание данных из формы
		brand := r.FormValue("brand")
		model := r.FormValue("model")
		processor := r.FormValue("processor")
		gpu := r.FormValue("gpu")
		ram, _ := strconv.Atoi(r.FormValue("ram"))
		storageCapacity, _ := strconv.Atoi(r.FormValue("storageCapacity"))
		screenSize, _ := strconv.ParseFloat(r.FormValue("screenSize"), 64)
		price, _ := strconv.Atoi(r.FormValue("price"))

		// SQL запрос на добавление нового ноутбука
		query := `INSERT INTO laptop (brand, model, processor, gpu, ram, storage_capacity, screen_size, price) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
		_, err := db.Exec(query, brand, model, processor, gpu, ram, storageCapacity, screenSize, price)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Перенаправление на главную страницу после успешного создания
		http.Redirect(w, r, "admin?brandFilter=&sortOrder=id", http.StatusSeeOther)
	})

	http.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Unsupported request method.", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}

		id, err := strconv.Atoi(r.FormValue("id"))
		if err != nil {
			http.Error(w, "Invalid ID format", http.StatusBadRequest)
			return
		}

		// SQL запрос на удаление ноутбука по ID
		query := `DELETE FROM laptop WHERE id = $1`
		_, err = db.Exec(query, id)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Перенаправление на главную страницу после успешного удаления
		http.Redirect(w, r, "admin?brandFilter=&sortOrder=id", http.StatusSeeOther)
	})

	http.HandleFunc("/editProfile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
			return
		}

		// Проверка наличия сессии пользователя
		session, ok := Sessions[r.RemoteAddr]
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Получение нового имени пользователя из формы
		newUsername := r.FormValue("username")

		// Валидация нового имени пользователя, если необходимо

		// Обновление имени пользователя в базе данных
		_, err := db.Exec("UPDATE users SET username = $1 WHERE email = $2", newUsername, session.Email)
		if err != nil {
			http.Error(w, "Failed to update profile", http.StatusInternalServerError)
			return
		}

		// Обновление сессии
		session.Username = newUsername
		Sessions[r.RemoteAddr] = session

		// Перенаправление на страницу профиля
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
	})

	http.HandleFunc("/changePassword", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Unsupported request method.", http.StatusMethodNotAllowed)
			return
		}

		session, ok := Sessions[r.RemoteAddr]
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		currentPassword := r.FormValue("current-password")
		newPassword := r.FormValue("new-password")
		confirmPassword := r.FormValue("confirm-password")

		var actualPassword string
		err := db.QueryRow("SELECT password FROM users WHERE email = $1", session.Email).Scan(&actualPassword)
		if err != nil {
			// Обработка ошибки запроса к БД
			http.Error(w, "Failed to retrieve user information.", http.StatusInternalServerError)
			return
		}

		// Проверка совпадения текущего пароля
		if actualPassword != currentPassword || newPassword != confirmPassword {
			http.Error(w, "Current password is incorrect or new password or new password and confirmation do not match", http.StatusBadRequest)
			return
		}

		// Если обе проверки пройдены, обновляем пароль
		_, err = db.Exec("UPDATE users SET password = $1 WHERE email = $2", newPassword, session.Email)
		if err != nil {
			http.Error(w, "Failed to change password.", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/profile", http.StatusSeeOther)
	})

	http.HandleFunc("/sendEmailToAll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Unsupported request method.", http.StatusMethodNotAllowed)
			return
		}

		subject := r.FormValue("subject")
		message := r.FormValue("message")

		// Получение списка всех email адресов из базы данных
		rows, err := db.Query("SELECT email FROM users")
		if err != nil {
			http.Error(w, "Failed to retrieve users.", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var emails []string
		for rows.Next() {
			var email string
			if err := rows.Scan(&email); err != nil {
				continue // Пропускаем ошибочные адреса
			}
			emails = append(emails, email)
		}

		// Отправка сообщения всем пользователям
		for _, email := range emails {
			err := sendEmail(email, subject, message) // Реализуйте функцию sendEmail самостоятельно
			if err != nil {
				// Здесь может быть логирование ошибок отправки
				continue
			}
		}

		// Перенаправление обратно в админ панель с сообщением об успехе (или отображение сообщения об успехе непосредственно на странице)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	})

	// Обработчик для статических файлов
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/verify", verifyHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/addToCart", addToCartHandler)
	http.HandleFunc("/cart", cartHandler)
	http.HandleFunc("/removeFromCart", removeFromCartHandler)

	

	err = http.ListenAndServe(":8000", nil)
	if err != nil {
	}

}


func removeFromCartHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
        return
    }

    // Убедитесь, что запрос содержит ID товара для удаления
    if err := r.ParseForm(); err != nil {
        http.Error(w, "Error parsing form", http.StatusBadRequest)
        return
    }
    id := r.FormValue("id")

    // Удаляем товар из таблицы laptop_cart
    _, err := db.Exec("DELETE FROM laptop_cart WHERE id = $1", id)
    if err != nil {
        http.Error(w, "Failed to remove item from cart", http.StatusInternalServerError)
        return
    }

    // Перенаправляем пользователя обратно на страницу корзины
    http.Redirect(w, r, "/cart", http.StatusSeeOther)
}


func addToCartHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
        return
    }

    // Парсим форму для получения ID товара
    err := r.ParseForm()
    if err != nil {
        http.Error(w, "Error parsing form", http.StatusBadRequest)
        return
    }
    id := r.FormValue("id")

    // Получаем данные товара из таблицы laptop
    var laptop Laptop
    err = db.QueryRow("SELECT * FROM laptop WHERE id = $1", id).Scan(&laptop.ID, &laptop.Brand, &laptop.Model, &laptop.Processor, &laptop.GPU, &laptop.RAM, &laptop.StorageCapacity, &laptop.ScreenSize, &laptop.Price)
    if err != nil {
        http.Error(w, "Laptop not found", http.StatusNotFound)
        return
    }

    // Добавляем товар в таблицу laptop_cart
    _, err = db.Exec("INSERT INTO laptop_cart (id, brand, model, processor, gpu, ram, storage_capacity, screen_size, price) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        laptop.ID, laptop.Brand, laptop.Model, laptop.Processor, laptop.GPU, laptop.RAM, laptop.StorageCapacity, laptop.ScreenSize, laptop.Price)
    if err != nil {
        http.Error(w, "Failed to add to cart", http.StatusInternalServerError)
        return
    }

    // Перенаправляем пользователя обратно на главную страницу
    http.Redirect(w, r, "/main", http.StatusSeeOther)
}

func cartHandler(w http.ResponseWriter, r *http.Request) {
    rows, err := db.Query("SELECT * FROM laptop_cart")
    if err != nil {
        http.Error(w, "Failed to get cart items", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var laptops []Laptop
    for rows.Next() {
        var laptop Laptop
        err := rows.Scan(&laptop.ID, &laptop.Brand, &laptop.Model, &laptop.Processor, &laptop.GPU, &laptop.RAM, &laptop.StorageCapacity, &laptop.ScreenSize, &laptop.Price)
        if err != nil {
            http.Error(w, "Failed to read cart items", http.StatusInternalServerError)
            return
        }
        laptops = append(laptops, laptop)
    }

    // Отображаем страницу корзины с товарами
    tmpl, err := template.ParseFiles("cartPage.html") // Создайте cartPage.html аналогично mainPage.html
    if err != nil {
        http.Error(w, "Failed to load cart page template", http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, laptops)
}



func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
	  renderLoginPage(w, "") // Передаем пустую строку для ошибки
	  return
	}
  
	if r.Method != http.MethodPost {
	  http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	  return
	}
	// Получение данных формы
	username := r.FormValue("username")
	password := r.FormValue("password")
  
	// Проверка логина и пароля
	if isValidLogin(db, username, password) {
	  // Получение данных пользователя из базы данных
	  user, err := getUserFromDB(username)
	  if err != nil {
		http.Error(w, "Failed to get user data", http.StatusInternalServerError)
		return
	  }
  
	  // Сохранение данных пользователя в сессии
	  session := Session{
		Username: user.Username,
		Email:    user.Email,
		Password: user.Password,
		Role:     user.Role,
	  }
	  Sessions[r.RemoteAddr] = session
  
	  // Перенаправление пользователя на главную страницу
	  http.Redirect(w, r, "/main", http.StatusSeeOther)
	  return
	}
  
	renderLoginPage(w, "Invalid username or password")
  }
  

func getUserFromDB(username string) (User, error) {
	// Запрос к базе данных для получения данных пользователя по имени пользователя
	row := db.QueryRow("SELECT * FROM users WHERE username = $1", username)

	// Создание пустой структуры для хранения данных пользователя
	user := User{}

	// Сканирование данных из результата запроса в структуру пользователя
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Role)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func renderLoginPage(w http.ResponseWriter, errorMessage string) {
	tmpl, err := template.ParseFiles("static/login.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := struct {
		Error    string
		HasError bool // Добавляем флаг для проверки наличия ошибки
	}{
		Error:    errorMessage,
		HasError: errorMessage != "", // Устанавливаем флаг в true, если есть сообщение об ошибке
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем сессию пользователя по его IP-адресу
	session, ok := Sessions[r.RemoteAddr]
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Здесь может быть логика для страницы после входа
	fmt.Fprintf(w, "Welcome, %s!", session.Username)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderRegisterPage(w, "", "") // Передаем пустые строки для ошибок
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	passwordField := r.FormValue("password")

	if username == "" || email == "" || passwordField == "" {
		renderRegisterPage(w, "All fields are required", "")
		return
	}

	// Проверяем уникальность логина
	if !isUsernameUnique(username) {
		renderRegisterPage(w, "Username is already taken", "")
		return
	}

	// Проверяем уникальность email
	if !isEmailUnique(email) {
		renderRegisterPage(w, "Email is already registered", "")
		return
	}

	// Генерация случайного 6-значного кода
	code := generateRandomNumber(100000, 999999)
	saveCodeToFile(code)
	

	// Отправка кода подтверждения на почту
	err := sendVerificationEmail(email, code)
	if err != nil {
		http.Error(w, "Failed to send verification email", http.StatusInternalServerError)
		return
	}

	// Сохраняем данные пользователя в сессии
	session := Session{
		Username:         username,
		Email:            email,
		Password:         passwordField,
		VerificationCode: code,
		Role:             "user",
	}
	Sessions[r.RemoteAddr] = session

	// Перенаправляем пользователя на страницу для ввода кода подтверждения
	http.Redirect(w, r, "/verify", http.StatusSeeOther)
}

func saveCodeToFile(code int) error {
    // Convert the code to a string
    codeStr := strconv.Itoa(code)

    // Write the code string to a file named code.txt
    // 0666 is a permission setting that allows reading and writing by all users
    err := ioutil.WriteFile("code.txt", []byte(codeStr), 0666)
    if err != nil {
        return err // Return the error to be handled by the caller
    }

    return nil // No error occurred
}


func renderRegisterPage(w http.ResponseWriter, usernameError, emailError string) {
	tmpl, err := template.ParseFiles("static/register.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, struct {
		UsernameError string
		EmailError    string
	}{
		UsernameError: usernameError,
		EmailError:    emailError,
	})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Функция проверки уникальности логина
func isUsernameUnique(username string) bool {
	// Выполнение запроса к базе данных для проверки наличия пользователя с таким логином
	row := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1", username)
	var count int
	err := row.Scan(&count)
	if err != nil {
		// Обработка ошибки при выполнении запроса
		fmt.Println("Error checking username uniqueness:", err)
		return false
	}
	// Если количество пользователей с данным логином больше нуля, значит логин не уникален
	return count == 0
}

// Функция проверки уникальности email
func isEmailUnique(email string) bool {
	// Выполнение запроса к базе данных для проверки наличия пользователя с таким email
	row := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1", email)
	var count int
	err := row.Scan(&count)
	if err != nil {
		// Обработка ошибки при выполнении запроса
		fmt.Println("Error checking email uniqueness:", err)
		return false
	}
	// Если количество пользователей с данным email больше нуля, значит email не уникален
	return count == 0
}

func isValidLogin(db *sql.DB, username, password string) bool {
	// Запрос к базе данных для получения пароля по имени пользователя
	row := db.QueryRow("SELECT password FROM users WHERE username = $1", username)
  
	// Переменная для хранения фактического пароля из базы данных
	var actualPassword string
  
	// Сканирование значения из результата запроса в переменную actualPassword
	err := row.Scan(&actualPassword)
	if err != nil {
	  // Если произошла ошибка при запросе (например, пользователь не найден), возвращаем false
	  return false
	}
  
	// Сравниваем введенный пароль с фактическим паролем из базы данных
	return password == actualPassword
  }
  

func generateRandomNumber(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min+1) + min
}

func sendVerificationEmail(email string, code int) error {
	// Учетные данные SMTP-сервера
	auth := smtp.PlainAuth("", "killme.rayyxd@gmail.com", "ztko ltho bcel febo", "smtp.gmail.com")

	// Получатель письма
	to := []string{email}

	// Формирование сообщения с кодом
	message := fmt.Sprintf("To: %s\r\n"+
		"Subject: Verification Code\r\n"+
		"\r\n"+
		"Your verification code is: %d", email, code)

	// Отправка письма
	err := smtp.SendMail("smtp.gmail.com:587", auth, "killme.rayyxd@gmail.com", to, []byte(message))
	if err != nil {
		fmt.Println("Error sending verification email:", err)
		return err
	}
	return nil
}

func sendEmail(to, subject, messageText string) error {
	// Учетные данные SMTP-сервера
	auth := smtp.PlainAuth("", "killme.rayyxd@gmail.com", "ztko ltho bcel febo", "smtp.gmail.com")

	// Формирование сообщения
	message := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		messageText)

	// Отправка письма
	err := smtp.SendMail("smtp.gmail.com:587", auth, "killme.rayyxd@gmail.com", []string{to}, message)
	if err != nil {
		fmt.Println("Error sending email:", err)
		return err
	}
	return nil
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderVerifyPage(w, "")
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получаем введенный пользователем код подтверждения
	codeStr := r.FormValue("code")
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		renderVerifyPage(w, "Invalid verification code")
		return
	}

	// Получаем сессию пользователя по его IP-адресу
	session, ok := Sessions[r.RemoteAddr]
	if !ok {
		renderVerifyPage(w, "Session not found")
		return
	}

	// Проверяем совпадение введенного кода и кода из сессии
	if code != session.VerificationCode {
		renderVerifyPage(w, "Invalid verification code")
		return
	}

	// Определение роли пользователя
	var role string
	if session.Email == "sybbka.of@mail.ru" || session.Email == "abdukarimov.05@gmail.com" {
		role = "admin"
	} else {
		role = "user"
	}

	// Сохранение пользователя в базе данных
	err = saveUserToDB(session.Username, session.Email, session.Password, role)
	if err != nil {
		http.Error(w, "Failed to save user to database", http.StatusInternalServerError)
		return
	}

	// Сохраняем роль пользователя в сессии
	session.Role = role

	// Обновляем сессию в хранилище сессий
	Sessions[r.RemoteAddr] = session

	// Перенаправляем пользователя на страницу /main
	http.Redirect(w, r, "/main", http.StatusSeeOther)
}

func renderVerifyPage(w http.ResponseWriter, errorMessage string) {
	tmpl, err := template.ParseFiles("static/verify.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, struct{ Error string }{Error: errorMessage})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func saveUserToDB(username, email, password, role string) error {
	// Создание запроса SQL для вставки нового пользователя в таблицу
	query := `
       INSERT INTO users (username, email, password, role)
       VALUES ($1, $2, $3, $4)
   `
	// Выполнение запроса к базе данных
	_, err := db.Exec(query, username, email, password, role)
	if err != nil {
		// Обработка ошибки при выполнении запроса
		return err
	}
	return nil
}



type Laptop struct {
	ID              int
	Brand           string
	Model           string
	Processor       string
	GPU             string
	RAM             int
	StorageCapacity int
	ScreenSize      float64
	Price           int
}
