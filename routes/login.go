package routes

import (
	"log"
	"net/http"

	"github.com/bitterspread/mediax/auth"
	"github.com/bitterspread/mediax/config"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if auth.IsAuthenticated(r) {
			http.Redirect(w, r, "/home", http.StatusFound)
			return
		}
		renderLogin(w, nil)
	} else if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == config.App.User.Username && config.App.User.CheckPassword(password) {
			err := auth.CreateSession(w)
			if err != nil {
				log.Printf("Error creating session: %v", err)
				handleError(w, "Internal Server Error: Failed to create session", "login", 500)
			}
			http.Redirect(w, r, "/home", http.StatusFound)
		} else {
			log.Printf("Login failed for user '%s'.", username)
			handleError(w, "Invalid username or password", "login", 401)
		}
	} else {
		handleError(w, "Method not allowed", "login", 405)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	auth.DeleteSession(w, r)
	http.Redirect(w, r, "/login", http.StatusFound)
}
