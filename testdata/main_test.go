package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func BenchmarkOptions(b *testing.B) {
	b.ReportAllocs()
	req, err := http.NewRequest("GET", "/users", nil)
	assert.NoError(b, err)
	svc := &Service{users: []User{{ID: 1, Name: "Alice"}, {ID: 2, Name: "Bob"}}}
	for i := 0; i < b.N; i++ {
		svc.HandlerOptions(req)
	}
}

func BenchmarkRouting(b *testing.B) {
	b.ReportAllocs()
	req, err := http.NewRequest("GET", "/users", nil)
	assert.NoError(b, err)
	svc := &Service{users: []User{{ID: 1, Name: "Alice"}, {ID: 2, Name: "Bob"}}}
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		svc.ServeHTTP(w, req)
	}
}
