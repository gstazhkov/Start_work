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

	"github.com/gorilla/sessions" // Используем gorilla/sessions для сессий
	_ "github.com/mattn/go-sqlite3"
)

// Структура для хранения учетных данных (хеш пароля)
type Credentials struct {
	Username     string
	PasswordHash string
}

// Глобальная переменная для базы данных
var db *sql.DB

// Глобальная переменная для хранения сессий
var sessionStore *sessions.CookieStore

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

// Функция для проверки существования пользователя
func userExists(username string) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		log.Println("Ошибка при проверке пользователя:", err)
		return false
	}
	return count > 0
}

// Функция для сохранения учетных данных в базе данных
func saveUser(username, passwordHash string) error {
	_, err := db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, passwordHash)
	return err
}

// Функция для получения хеша пароля из базы данных по логину
func getPasswordHash(username string) (string, error) {
	var passwordHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&passwordHash)
	return passwordHash, err
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

	if username == "" || password == "" {
		http.Error(w, "Пожалуйста, заполните все поля.", http.StatusBadRequest)
		return
	}

	if userExists(username) {
		http.Error(w, "Пользователь с таким логином уже существует.", http.StatusBadRequest)
		return
	}

	hashedPassword := hashPassword(password)
	err := saveUser(username, hashedPassword)
	if err != nil {
		log.Println("Ошибка сохранения пользователя:", err)
		http.Error(w, "Ошибка регистрации.", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Зарегистрирован новый пользователь: Логин=%s\n", username)

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

	// Создание таблицы users, если она не существует
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			password_hash TEXT
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Генерация случайного ключа сессии
	sessionKey := generateSessionKey()

	// Инициализация сессий с настройками
	sessionStore = sessions.NewCookieStore(sessionKey)
	sessionStore.Options.MaxAge = 23 * 60 * 60 // 23 часа в секундах
	sessionStore.Options.HttpOnly = true       // Запретить доступ к куке через JavaScript

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
