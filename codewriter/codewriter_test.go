package codewriter_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/thnxdev/happy/codewriter"
)

func TestCodeWriter(t *testing.T) {
	w := codewriter.New("pkg")
	w.Lf("func hello() {")
	w.In(func(w *codewriter.Writer) {
		w.Lf(`println("hello")`)
	})
	w.Lf("}")
	expected := `func hello() {
  println("hello")
}
`
	assert.Equal(t, expected, w.Body())
}
