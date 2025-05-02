package routes

import (
	"log"
	"net/http"
	"os"

	"github.com/bitterspread/mediax/auth"
	"github.com/bitterspread/mediax/config"
	"github.com/bitterspread/mediax/handlers"
	"github.com/bitterspread/mediax/web"
)

var protectedMux = http.NewServeMux()
var apiMux = http.NewServeMux()

func setupRoutes() {
	var err error

	staticFS, err = web.GetStaticFileSystem()
	if err != nil {
		log.Fatal(err)
	}

	// Image dir
	imageDir := config.ImageDir
	if _, err := os.Stat(imageDir); os.IsNotExist(err) {
		err := os.MkdirAll(imageDir, os.ModePerm)
		if err != nil {
			log.Fatalf("Failed to create image directory <%s>: %v", imageDir, err)
		}
		log.Printf("Image directory <%s> did not exist, it has been created automatically", imageDir)
	}
	imageFS := os.DirFS(imageDir)

	// Static files
	staticFileHandler := handlers.ServeStaticFiles("/static/", staticFS)
	imageFileHandler := handlers.ServeStaticFiles("/images/", imageFS)

	cachedStaticHandler := auth.CacheControlMiddleware(staticFileHandler)
	cachedImageHandler := auth.CacheControlMiddleware(imageFileHandler)

	securedCachedStaticHandler := auth.SecurityHeadersMiddleware(cachedStaticHandler)
	securedCachedImageHandler := auth.SecurityHeadersMiddleware(cachedImageHandler)

	// Routes
	protectedMux.Handle("/static/", securedCachedStaticHandler)
	protectedMux.Handle("/images/", securedCachedImageHandler)

	http.HandleFunc("/login", handleLogin)

	protectedMux.HandleFunc("/logout", handleLogout)

	protectedMux.HandleFunc("/", redirectToHome)
	protectedMux.HandleFunc("/home", handleHomePage)
	protectedMux.HandleFunc("/book", handleCategory)
	protectedMux.HandleFunc("/movie", handleCategory)
	protectedMux.HandleFunc("/tv", handleCategory)
	protectedMux.HandleFunc("/anime", handleCategory)
	protectedMux.HandleFunc("/game", handleCategory)

	protectedMux.HandleFunc("/book/", handleSubject)
	protectedMux.HandleFunc("/movie/", handleSubject)
	protectedMux.HandleFunc("/tv/", handleSubject)
	protectedMux.HandleFunc("/anime/", handleSubject)
	protectedMux.HandleFunc("/game/", handleSubject)

	protectedMux.HandleFunc("/add", handleAdd)
	protectedMux.HandleFunc("/add/subject", handleAddSubject)

	protectedMux.HandleFunc("/search", handleSearch)

	apiMux.HandleFunc("/api/v0/collection", handlers.HandleAPI)

	http.Handle("/", auth.SecurityHeadersMiddleware(auth.AuthMiddleware(protectedMux)))
	http.Handle("/api/", auth.APIAuthMiddleware(config.App.ApiKey)(apiMux))
}
