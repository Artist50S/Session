package main

import (
	"encoding/gob"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

//Пользователь хранит информацию об учетной записи пользователя
type User struct {
	UserName      string
	Authenticated bool
}

// store будет хранить все данные сеанса
var store *sessions.CookieStore

// tpl содержит все проанализированные шаблоны
var tpl *template.Template

func init() {
	//Рекомендуется использовать аутентификационный ключ размером 32 или 64 байта.
	authKeyOne := securecookie.GenerateRandomKey(64)
	//Ключ шифрования, если он установлен, должен быть 16, 24 или 32 байта для выбора режимов AES-128, AES-192 или AES-256.
	//encryptionKeyOne := securecookie.GenerateRandomKey(32)
	store = sessions.NewCookieStore(
		authKeyOne,
		//encryptionKeyOne,
	)
	//установили максимальный возраст в 15 минут и HttpOnly в true, чтобы сеанс не мог быть изменен javascript
	store.Options = &sessions.Options{
		MaxAge:   60 * 15,
		HttpOnly: true,
	}
	//регистрируем пользовательский тип пользователя в пакете кодирования gob
	gob.Register(User{})
	//разбираем все шаблоны в папке templates
	tpl = template.Must(template.ParseGlob("C:/Users/tema-/projects/test/source/session/Gorilla/template/*.gohtml"))
}
func main() {
	router := mux.NewRouter()
	router.HandleFunc("/", index)
	router.HandleFunc("/login", login)
	router.HandleFunc("/logout", logout)
	router.HandleFunc("/forbidden", forbidden)
	router.HandleFunc("/secret", secret)
	http.ListenAndServe(":8080", router)

}
func login(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Println("login1", session)
	//authorization
	if r.FormValue("code") != "code" {
		if r.FormValue("code") == "" {
			//перед перенаправлением флэш-значение добавляется в сеанс
			//использоваться для отображения ошибок, и они сохраняются до чтения.
			session.AddFlash("must enter a code")
		}
		session.AddFlash("the code was incorrect")
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "forbidden", http.StatusFound)
	}
	//извлекаем имя пользователя из формы и создаем новый объект пользователя
	username := r.FormValue("username")
	//добавляется в сеанс.Карта ценностей. Эта карта имеет тип map[interface{}]interface{}
	//используем строковый ключ “user” для хранения пользовательского значения
	user := &User{
		UserName:      username,
		Authenticated: true,
	}
	session.Values["user"] = user
	//Каждый раз, когда сеанс изменяется, мы должны сохранять его
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	log.Println("login2", session)
	http.Redirect(w, r, "/secret", http.StatusFound)
}

//выход из системы отменяет аутентификацию пользователя
func logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["user"] = User{}
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Println("logout", session)
	http.Redirect(w, r, "/", http.StatusFound)
}

//индекс служит индексным HTML файлом
func index(w http.ResponseWriter, r *http.Request) {
	//сеанс извлекается из файлов cookie
	session, err := store.Get(r, "coookie-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//возвращает пользователя из сеанса
	user := getUser(session)
	log.Println("/", session)
	//Пользователь передается шаблону, чтобы определить, аутентифицирован ли сеанс или нет
	//Шаблон index.gohtml будет визуализироваться на основе .Authenticatedсвойства пользователя
	tpl.ExecuteTemplate(w, "index.gohtml", user)
}

//secret отображает секретное сообщение для авторизованных пользователей
func secret(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Println("secret1", session)
	user := getUser(session)
	if auth := user.Authenticated; !auth {
		session.AddFlash("you dont have access")
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/forbidden", http.StatusFound)
		return
	}
	tpl.ExecuteTemplate(w, "secret.gohtml", user.UserName)
}
func forbidden(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//все ошибки flash считываются//
	//создает []interface{}сохраненные в flashMessages
	flashMassages := session.Flashes()
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//Шаблон будет использовать цикл для печати всех сообщений для пользователя
	tpl.ExecuteTemplate(w, "forbodden.gohtml", flashMassages)
}

// getUser возвращает пользователя из сеансов
// on error возвращает пустой пользователь
func getUser(s *sessions.Session) User {
	value := s.Values["user"]
	var user = User{}
	user, ok := value.(User)
	if !ok {
		return User{Authenticated: false}
	}
	return user
}
