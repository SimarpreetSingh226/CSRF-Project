package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/justinas/alice"
	"github.com/simar/golang-csrf-project/db"
	myjwt "github.com/simar/golang-csrf-project/server/middleware/myJwt"
	"github.com/simar/golang-csrf-project/server/templates"
)

func NewHandler() http.Handler{
	return alice.New(recoverHandler,authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler)http.Handler{
	fn := func(w http.ResponseWriter, r *http.Request){
		defer func(){
			if err := recover(); err!=nil{
				log.Panic("Recovered! Panic:%+v",err)
				http.Error(w,http.StatusText(500),50)
			}
		}()
		next.ServeHTTP(w,r)
	}
	return http.HandlerFunc(fn)
}
func authHandler(next http.Handler)http.Handler{
	fn := func(w http.ResponseWriter, r *http.Request){
		switch r.URL.Path{
		case "/restricted","/logout","deleteUser":
		default:
		}
	}
}

func logicHandler(w http.ResponseWriter, r * http.Request){
	switch r.URL.Path{
	case "/restricted":
		csrfSecret := grabCsrfFromReq(r)
		templates.RenderTemplate(w,"restricted",&templates.RestrictedPage{csrfSecret, "Hello Simar"})
	case "/login":
		switch r.Method{
			case "GET":
			case "POST":
			default:
		}
		case "/register":
		switch r.Method {
			case "GET":
				templates.RenderTemplate(w,"register",&templates.RegisterPage{false,""})
			case "POST":
				r.ParseForm()
				log.Println(r.Form)
				_,uuid,err := db.FetchUserByUsername(strings.Join(r.Form["username"],""))
				if err!=nil{
					w.WriteHeader(http.StatusUnauthorized)
				}else{
					role := "user"
					uuid,err = db.StoreUser(strings.Join(r.Form["username"],""),strings.Join(r.Form["password"],""),role)
				}
				if err!=nil{
					http.Error(w,http.StatusText(500),500)
				}
				log.Panicln("uuid: "+uuid)
				myjwt.CreateNewTokens()
			default:
		}
	case "/logout":
	case "/deleteUser":
	default:
	}
}

func nullifyTokenCookies(w *http.ResponseWriter,r *http.Request){
	authCookies := http.Cookie{
		Name:"AuthToken",
		Value:"",
		Expires: time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w,&authCookies)

	refreshCookies := http.Cookie{
		Name:"refreshToken",
		Value:"",
		Expires: time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w,&refreshCookies)

	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie{
		return
	} else if refreshErr != nil{
		log.Panic("panic: %+v",refreshErr)
		http.Error(*w,http.StatusText(500),50)
	}
	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter,authTokenString string, refreshTokenString string){
	authCookie:=http.Cookie{
		Name:"AuthToken",
		Value:authTokenString,
		HttpOnly: true,
	}	
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:"RefreshToken",
		Value: refreshTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string{
	csrfFrom := r.FormValue("X-SCRF-Token")
	if csrfFrom != ""{
		return csrfFrom
	} else{
		return r.Header.Get("X-SCRF-Token")
	}
}