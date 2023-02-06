//go:generate happy
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// An Error that implements http.Handler to write structured JSON errors.
type Error struct {
	code    int
	message string
}

func Errorf(code int, format string, args ...interface{}) error {
	return Error{code, fmt.Sprintf(format, args...)}
}

func (e Error) Error() string { return e.message }

func (e Error) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.code)
	json.NewEncoder(w).Encode(map[string]string{"error": e.message})
}

type ID int

func (i *ID) UnmarshalJSON(data []byte) error {
	id, err := strconv.Atoi(string(data))
	if err != nil {
		return err
	}
	*i = ID(id)
	return nil
}

func (i *ID) UnmarshalText(text []byte) error {
	id, err := strconv.Atoi(string(text))
	if err != nil {
		return err
	}
	*i = ID(id)
	return nil
}

type User struct {
	ID   ID     `json:"id"`
	Name string `json:"name"`
}

type Service struct {
	users []User
}

// GetUser by ID.
//
//happy:api GET /users/:id
func (s *Service) GetUser(id ID) (User, error) {
	for _, user := range s.users {
		if user.ID == id {
			return user, nil
		}
	}
	return User{}, Errorf(http.StatusNotFound, "user %d not found", id)
}

//happy:api GET /users/:id/avatar
func (s *Service) GetAvatar(id ID) ([]byte, error) {
	return nil, Errorf(http.StatusNotFound, "avatar %d not found", id)
}

//happy:api POST /users authenticated
func (s *Service) CreateUser(r *http.Request, user User) error {
	username := r.Context().Value(AuthenticatedUser)
	log.Printf("Authenticated user %s", username)
	for _, u := range s.users {
		if u.ID == user.ID {
			return Errorf(http.StatusConflict, "user %d already exists", user.ID)
		}
	}
	s.users = append(s.users, user)
	return nil
}

type Paginate struct {
	Page   int
	Size   int
	Sparse bool
}

//happy:api GET /users
func (s *Service) ListUsers(paginate Paginate) ([]User, error) {
	return s.users, nil
}

//happy:api POST /shutdown
func (s *Service) Shutdown(w http.ResponseWriter) {
	fmt.Fprintln(w, "Shutting down...")
	go func() { time.Sleep(time.Second); os.Exit(0) }()
}

type HAPIOptions interface {
	HandlerOptions(*http.Request) map[string]string
}

type HAPIHandler interface {
	http.Handler
	HAPIOptions
}

type forwardHAPIHandler struct {
	HAPIOptions
	http.HandlerFunc
}

var Options struct{}

type HAPIService interface {
	HandlerOptions(*http.Request) map[string]string
}

// OptionsMiddleware adds the HAPIOptions to the request context under the key Options.
func OptionsMiddleware(svc HAPIService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), Options, svc.HandlerOptions(r))
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

var AuthenticatedUser struct{}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		options := r.Context().Value(Options).(map[string]string)
		_, authenticated := options["authenticated"]
		if !authenticated {
			next.ServeHTTP(w, r)
			return
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "alice" || password != "secret" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), AuthenticatedUser, username)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func main() {
	service := &Service{
		users: []User{{ID: 1, Name: "Alice"}, {ID: 2, Name: "Bob"}},
	}
	const address = "127.0.0.1:8080"
	log.Printf("Starting server on http://%s\n", address)
	http.ListenAndServe(address, OptionsMiddleware(service, AuthMiddleware(service)))
}
