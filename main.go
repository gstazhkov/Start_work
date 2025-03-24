package main

import (
	"html/template"
	"log"
	"net/http"
	"time"
)

func main() {
	// Настраиваем обработчик для корневого пути
	http.HandleFunc("/", timeHandler)

	// Запускаем сервер на порту 8080
	log.Println("Сервер запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func timeHandler(w http.ResponseWriter, r *http.Request) {
	// Загружаем часовые пояса
	londonLoc, err := time.LoadLocation("Europe/London")
	if err != nil {
		http.Error(w, "Ошибка загрузки часового пояса Лондона", http.StatusInternalServerError)
		return
	}

	moscowLoc, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		http.Error(w, "Ошибка загрузки часового пояса Москвы", http.StatusInternalServerError)
		return
	}

	// Получаем текущее время
	now := time.Now()
	londonTime := now.In(londonLoc)
	moscowTime := now.In(moscowLoc)

	// Создаем HTML-шаблон
	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Текущее время</title>
	</head>
	<body>
		<h1>Текущее время</h1>
		<p>Лондон: {{.London}}</p>
		<p>Москва: {{.Moscow}}</p>
	</body>
	</html>`

	// Парсим шаблон
	t, err := template.New("time").Parse(tmpl)
	if err != nil {
		http.Error(w, "Ошибка обработки шаблона", http.StatusInternalServerError)
		return
	}

	// Данные для шаблона
	data := struct {
		London string
		Moscow string
	}{
		London: londonTime.Format("15:04:05, 02 Jan 2006"),
		Moscow: moscowTime.Format("15:04:05, 02 Jan 2006"),
	}

	// Выполняем шаблон и отправляем ответ
	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, "Ошибка вывода страницы", http.StatusInternalServerError)
	}
}
