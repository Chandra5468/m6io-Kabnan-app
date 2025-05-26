package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

type App struct {
	DB     *sql.DB
	JWTKey []byte
}

type Credentials struct {
	SeqNo    int    `json:"seq_no"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Claims struct {
	Username string `json:"username"`
	SeqNo    int    `json:"seq_no"`
	jwt.RegisteredClaims
}

type UserResponse struct {
	SeqNo    int    `json:"seq_no"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

type ErrorMessage struct {
	Message string `json:"message"`
}

type RouterResp struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"`
}

func main() {

	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Erro loading .env file %s", err.Error())
	}

	JWTKey := []byte(os.Getenv("JWT_SECRET"))

	if len(JWTKey) == 0 {
		log.Fatal("JWT_SECRET ENV VARIABLE is not set")
	}
	connString := os.Getenv("POSTGRES_URL")

	if len(connString) == 0 {
		log.Fatal("Postgresql string not available")
	}

	db, err := sql.Open("postgres", connString)

	if err != nil {
		log.Fatalf("Error opening psql %s", err.Error())
	}

	defer db.Close()

	app := &App{
		DB: db,
	}

	log.Println("Setting up routes")

	// router := http.NewServeMux()
	router := mux.NewRouter()
	router.Use(loggingMiddleware)
	router.HandleFunc("/register", app.register).Methods("POST")
	router.HandleFunc("/login", app.login).Methods("POST")
	router.HandleFunc("/projects", createProject).Methods("POST")
	router.HandleFunc("/projects/{id}", updateProject).Methods("PUT")
	router.HandleFunc("/projects", getProjects).Methods("GET")
	router.HandleFunc("/projects/{id}", getProject).Methods("GET")
	router.HandleFunc("/projects/{id}", deleteProject).Methods("DELETE")

	log.Println("Starting server at 5001")
	http.ListenAndServe(":5001", router)
}

// Middleware

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		log.Printf("%s %s %s \n", r.RemoteAddr, r.Method, r.URL)
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func (app *App) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			respondWithError(w, http.StatusBadRequest, "missing authorization token")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			return app.JWTKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				respondWithError(w, http.StatusUnauthorized, "invalid token signature")
				return
			}
			respondWithError(w, http.StatusBadRequest, "invalid token")
			return
		}

		if !token.Valid {
			respondWithError(w, http.StatusUnauthorized, "token expired")
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateMiddleware(schema string) func(http.Handler) http.Handler { // Generally middlewares take a handler and returns handler. In this case a string is taken and handler is returned
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]interface{}

			err := json.NewDecoder(r.Body).Decode(&body)

			if err != nil {
				respondWithError(w, http.StatusBadRequest, "invalid request payload or json parsing error in validation")
				return
			}

		})
	}
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(&ErrorMessage{Message: message})
}

func (app *App) generateToken(username *string, seqNo *int) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &Claims{
		Username: *username,
		SeqNo:    *seqNo,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(app.JWTKey)

	if err != nil {
		log.Println("Error jwt", err)
		return "", err
	}

	return tokenString, nil
}

// Register function to handle user registration
func (app *App) register(w http.ResponseWriter, r *http.Request) {
	cred := &Credentials{}
	err := json.NewDecoder(r.Body).Decode(cred)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request. Payload not proper")
		return
	}

	hashPasswordByte, err := bcrypt.GenerateFromPassword([]byte(cred.Password), bcrypt.DefaultCost)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error hashing password")
		return
	}

	var userId int // Will return seqno on successful execution

	err = app.DB.QueryRow("insert into users (username, password) values ($1, $2) returning seqno", cred.Username, string(hashPasswordByte)).Scan(&userId)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error executing query for registring user")
		return
	}
	json.NewEncoder(w).Encode(&UserResponse{SeqNo: userId, Username: cred.Username})
}

// Login
func (app *App) login(w http.ResponseWriter, r *http.Request) {
	cred := &Credentials{}
	err := json.NewDecoder(r.Body).Decode(cred)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request. Payload not proper")
		return
	}

	storedCreds := &Credentials{}

	err = app.DB.QueryRow("select seqno, username, password from users where username = $1", cred.Username).Scan(&storedCreds.SeqNo, &storedCreds.Username, &storedCreds.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Invalid username or password")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Unable to execute fetch query in login")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(cred.Password))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "password not valid")
		return
	}

	tokenString, err := app.generateToken(&storedCreds.Username, &storedCreds.SeqNo)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "unable to generate jwt")
		return
	}
	json.NewEncoder(w).Encode(&UserResponse{SeqNo: storedCreds.SeqNo, Username: storedCreds.Username, Token: tokenString})
}

// Create Project
func createProject(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(&RouterResp{Message: "hello from c project"})
}

// Update Project
func updateProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	json.NewEncoder(w).Encode(&RouterResp{Message: "hello from u project", ID: id})
}

// Get Projects
func getProjects(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(&RouterResp{Message: "hello from g projects"})
}

// Get Project
func getProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	json.NewEncoder(w).Encode(&RouterResp{Message: "hello from g project", ID: id})
}

// Delete Project
func deleteProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	json.NewEncoder(w).Encode(&RouterResp{Message: "hello from d project", ID: id})
}
