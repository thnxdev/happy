# happy is an opinionated tool for generating request-handler boilerplate for Go 😊 [![CI](https://github.com/thnxdev/happy/actions/workflows/ci.yml/badge.svg)](https://github.com/thnxdev/happy/actions/workflows/ci.yml)

happy automatically generates `http.RequestHandler` boilerplate for routing to Go
methods annotated with comment directives. The generated code decodes the
incoming HTTP request into the method's parameters, and encodes method return
values to HTTP responses.

happy only supports JSON request/response payloads. That said, see
[below](#escape-hatch) for workarounds that can leverage just happy's routing.

happy's generated code relies on only the standard library.

Here's an example annotated method that happy will generate a request handler for:

```go
//happy:api GET /users/:id
func (u *UsersService) GetUser(id string) (User, error) {
	for _, user := range u.users {
		if user.ID == id {
			return user, nil
		}
	}
	return User{}, Errorf(http.StatusNotFound, "user %q not found", id)
}
```

The generated request handler will map the path component `:id` to the parameter
`id`, and JSON encode the response payload or error.

See [below](#example) for a full example.

# Status

happy is usable but has some limitations and missing features:

- Does not support pointers to structs for JSON request payloads, only values.
- Limited (int and string) type support for path and query parameters.
- Does not support embedded structs for query parameters.
- A command to dump the API as an OpenAPI schema.

# Protocol

happy's protocol is in the form of Go comment directives. Each directive must be
placed on a method, not a free function.

Annotations and methods are in the following form:

```go
//happy:api <method> <path> [<option>[=<value>] ...]
func (s Struct) Method([pathVar0, pathVar1 string][, req Request]) ([<response>, ][error]) { ... }
```

## Options

Options are key+value pairs appended to the end of an annotation and are exposed
via the following generated method on the service struct:

```go
HandlerOptions(r *http.Request) map[string]string
```

This method will return the metadata map associated with the inbound request, or
`nil`.

A handy pattern is to create a wrapping `http.Handler` that injects the options
into the inbound request context like so:

```go
var Options struct{}

type OptionHandler interface {
	HandlerOptions(*http.Request) map[string]string
}

func OptionsMiddleware(options OptionHandler, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), Options, options.HandlerOptions(r))
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
```

## Request signature

The `<path>` value supports variables in the form `:<name>` which are mapped
directly to method parameters of the same name. These parameters must implement
`encoding.TextUnmarshaler` or be of type `string` or `int`.

eg.

```go
//happy:api GET /users/:id
func (u *UsersService) GetUser(id string) (User, error) { ... }
```

In addition to path variables and the request payload, happy can pass any of the
following types to your handler method:

- `*http.Request`
- `http.ResponseWriter`
- `context.Context` from the incoming `*http.Request`
- `io.Reader` for the request body

### Request payload decoding

Finally, a single extra struct parameter can be specified, which will be decoded
from the request payload. For PUT/POST request the "payload" is the request
body, for all other request types the "payload" is the URL query parameters. 

eg.

```go
type Paginate struct {
	Size int
}

//happy:api GET /users/
func (u *UsersService) ListUsers(pagination Paginate) ([]User, error) {
	// ...
}
```

#### Query parameter decoding

For query parameters, embedded structs are not supported and fields may
(currently) only be of types `bool`, `int` and `string`.

The name of the query parameter will be the name of the Go field with the first
letter lower-cased. This can be overridden with the field tag `query:"<name>"`.

## Response signature

The return signature of the method is in the form:

```
[([<response>, ][error])]
```

That is, the method may return a response, an error, both, or nothing.

 Depending on the type of the `<response>` value, the response will be encoded
 in the following ways:

 | Type | Encoding |
 | ---- | -------- |
 | `nil`/omitted | 204 No Content |
 | `string` | `text/html` |
 | `[]byte` | `application/octet-stream` |
 | `io.Reader` | `application/octet-stream` |
 | `io.ReadCloser` | `application/octet-stream` |
 | `*http.Response` | Response structure is used as-is. |
 | `*` | `application/json` |

## Error handling

If the method returns an error, happy will generate code to check the error
and return an error response. If the error value implements `http.Handler` that
will be used to generate the response, otherwise a 500 response will be
generated.

A rudimentary HTTP error type might look like this:

```go
type Error struct {
	Code int
	Msg string
}

func (e Error) Error() string { return fmt.Sprintf("%d: %s", e.Code, e.Msg) }
func (e Error) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, w.Msg, e.Code)
}
```

Additionally, if the receiver implements the following interface it will be used
to write errors:

```go
type ErrorHandler interface {
}
```

## Escape hatch

If happy's default request/response handling is not to your liking, you can still
leverage happy's routing by accepting `*http.Request` and `http.ResponseWriter`
as parameters:

```go
//happy:api POST /users
func (s Struct) CreateUser(r *http.Request, w http.ResponseWriter) { ... }
```

# Example

Create a `main.go` with the following content and run `go generate`. happy will
create a `main_api.go` file implementing `http.Handler` for `*Service`.

```go
//go:generate happy
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
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

type User struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type Service struct {
	users []User
}

//happy:api GET /users/:id
func (s *Service) GetUser(id int) (User, error) {
	for _, user := range s.users {
		if user.ID == id {
			return user, nil
		}
	}
	return User{}, Errorf(http.StatusNotFound, "user %q not found", id)
}

//happy:api GET /users
func (s *Service) ListUsers() ([]User, error) {
	return s.users, nil
}

//happy:api POST /users
func (s *Service) CreateUser(user User) error {
	for _, u := range s.users {
		if u.ID == user.ID {
			return Errorf(http.StatusConflict, "user %d already exists", user.ID)
		}
	}
	s.users = append(s.users, user)
	return Errorf(http.StatusCreated, "user %d created", user.ID)
}

func main() {
	service := &Service{
		users: []User{{ID: 1, Name: "Alice"}, {ID: 2, Name: "Bob"}},
	}
	http.ListenAndServe(":8080", service)
}
```

*happy's annotations are vaguely inspired by [Encore](https://encore.dev/).*