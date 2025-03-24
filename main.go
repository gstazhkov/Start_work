package main

import (
	"html/template"
	"log"
	"net/http"
	"time"
)

type CityTime struct {
	Name string
	Time string
}

var selectedCities = []string{"Europe/London", "Europe/Moscow"} // Начальные города

func main() {
	http.HandleFunc("/", timeHandler)
	log.Println("Сервер запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func timeHandler(w http.ResponseWriter, r *http.Request) {
	// Обработка POST-запроса для добавления города
	if r.Method == "POST" {
		r.ParseForm()
		newCity := r.FormValue("timezone")
		if newCity != "" {
			// Проверяем, существует ли часовой пояс
			if _, err := time.LoadLocation(newCity); err == nil {
				// Добавляем только уникальные города
				exists := false
				for _, city := range selectedCities {
					if city == newCity {
						exists = true
						break
					}
				}
				if !exists {
					selectedCities = append(selectedCities, newCity)
				}
			}
		}
	}

	// Получаем текущее время для всех выбранных городов
	now := time.Now()
	cityTimes := []CityTime{}
	for _, tz := range selectedCities {
		loc, _ := time.LoadLocation(tz)
		cityTime := now.In(loc)
		cityTimes = append(cityTimes, CityTime{
			Name: tz,
			Time: cityTime.Format("15:04:05, 02 Jan 2006"),
		})
	}

	// HTML-шаблон
	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Текущее время</title>
	</head>
	<body>
		<h1>Текущее время</h1>
		<ul>
		{{range .Cities}}
			<li>{{.Name}}: {{.Time}}</li>
		{{end}}
		</ul>
		<form method="POST">
			<label for="timezone">Добавить город (часовой пояс):</label><br>
			<select name="timezone" id="timezone">
				<option value="Europe/London">Лондон (Europe/London)</option>
				<option value="Europe/Moscow">Москва (Europe/Moscow)</option>
				<option value="America/New_York">Нью-Йорк (America/New_York)</option>
				<option value="Asia/Tokyo">Токио (Asia/Tokyo)</option>
				<option value="Australia/Sydney">Сидней (Australia/Sydney)</option>
				<!-- Добавьте другие часовые пояса по желанию -->
			</select>
			<input type="submit" value="Добавить">
		</form>
		<p>Примечание: Указывайте часовые пояса в формате IANA (например, "Asia/Dubai").</p>
	</body>
	</html>`

	// Парсим и выполняем шаблон
	t, err := template.New("time").Parse(tmpl)
	if err != nil {
		http.Error(w, "Ошибка обработки шаблона", http.StatusInternalServerError)
		return
	}

	data := struct {
		Cities []CityTime
	}{
		Cities: cityTimes,
	}

	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, "Ошибка вывода страницы", http.StatusInternalServerError)
	}
}
