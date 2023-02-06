package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/alecthomas/kong"
	"github.com/fatih/structtag"
	"golang.org/x/tools/go/packages"

	"github.com/thnxdev/happy/codewriter"
)

var (
	version string = "dev"
	cli     struct {
		Version kong.VersionFlag `help:"Show version."`
		List    bool             `help:"List endpoints."`
		Pkg     string           `arg:"" help:"Package to scan for API definitions." default:"."`
	}
	fset = token.NewFileSet()
	// httpHandlerInterface     = mustLoadInterface("net/http", "Handler")
	textUnmarshalerInterface = mustLoadInterface("encoding", "TextUnmarshaler")
)

type directive struct {
	doc        string
	method     string
	pattern    string
	options    map[string]string
	pathParams []string
}

type endpoint struct {
	decl      *ast.FuncDecl
	fn        *types.Func
	signature *types.Signature
	directive directive
}

func main() {
	kctx := kong.Parse(&cli, kong.Vars{"version": version}, kong.Description(`
happy automatically generates http.RequestHandler boilerplate for routing to Go
methods annotated with comment directives. The generated code decodes the
incoming HTTP request into the method's parameters, and encodes method return
values to HTTP responses.

eg.

  //happy:api GET /users/:id
  func (s *Server) GetUserByID(id int) (User, error) {
	// ...
  }

See https://github.com/thnxdev/happy for more information.
`), kong.HelpOptions{WrapUpperBound: 90})
	pkgs, err := packages.Load(&packages.Config{
		Fset: fset,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
	}, cli.Pkg)
	kctx.FatalIfErrorf(err)

	if cli.List {
		err = listEndpoints(pkgs)
		kctx.FatalIfErrorf(err)
		kctx.Exit(0)
	}

	didWork := false
	for _, pkg := range pkgs {
		outPath, endpoints, err := extractEndpoints(pkg)
		kctx.FatalIfErrorf(err)
		if len(endpoints) == 0 {
			continue
		}
		didWork = true

		gctx := &genContext{
			Writer: codewriter.New(pkg.Name),
			pkg:    pkg,
		}
		gctx.Import("net/http", "io", "encoding/json", "strconv")
		for _, svcEndpoints := range endpoints {
			generateHandler(gctx, svcEndpoints, makeTree(svcEndpoints))
			kctx.FatalIfErrorf(err)
		}

		source := gctx.Bytes()
		formatted, err := format.Source(source)
		if err != nil {
			for i, line := range bytes.Split(source, []byte("\n")) {
				fmt.Printf("%3d: %s\n", i+1, line)
			}
			kctx.FatalIfErrorf(err)
		}
		err = os.WriteFile(outPath, formatted, 0600)
		kctx.FatalIfErrorf(err)
	}

	if !didWork {
		kctx.Fatalf("no annotated endpoints found, nothing to do")
	}
}

func listEndpoints(pkgs []*packages.Package) error {
	for _, pkg := range pkgs {
		_, endpoints, err := extractEndpoints(pkg)
		if err != nil {
			return fmt.Errorf("could not list endpoints: %w", err)
		}
		if len(endpoints) == 0 {
			continue
		}

		for _, handlerEndpoints := range endpoints {
			for _, endpoint := range handlerEndpoints {
				dir := endpoint.directive
				fmt.Printf("%s %s\n", dir.method, dir.pattern)
				if dir.doc != "" {
					for _, line := range strings.Split(strings.TrimSpace(dir.doc), "\n") {
						fmt.Println("  " + line)
					}
				}
			}
		}
	}
	return nil
}

func generateHandler(gctx *genContext, eps []endpoint, tree *tree) {
	var ptr string
	var recvType *types.Named
	recv := eps[0].signature.Recv().Type()
	if ptrt, ok := recv.(*types.Pointer); ok {
		ptr = "*"
		recvType = ptrt.Elem().(*types.Named)
	}
	w := gctx.Writer
	w.L("")
	w.L("func (h %s%s) HandlerOptions(r *http.Request) map[string]string {", ptr, recvType.Obj().Name())
	optionsEndpoints := []endpoint{}
	for _, ep := range eps {
		if len(ep.directive.options) > 0 {
			optionsEndpoints = append(optionsEndpoints, ep)
		}
	}
	optionsTree := makeTree(optionsEndpoints)
	w.In(func(w *codewriter.Writer) {
		optionsTree.Write(w, "return nil", func(w *codewriter.Writer, ep endpoint) {
			if len(ep.directive.options) == 0 {
				w.L("return nil")
				return
			}
			w.L("return %#v", ep.directive.options)
		})
		w.L("return nil")
	})
	w.L("}")
	w.L("")
	w.L("func (h %s%s) ServeHTTP(w http.ResponseWriter, r *http.Request) {", ptr, recvType.Obj().Name())
	w = w.Push()
	w.L("var err error")
	w.L("var res any")
	tree.Write(w, "return", func(w *codewriter.Writer, ep endpoint) {
		if err := genEndpoint(gctx, w, ep); err != nil {
			pos := gctx.Pos(ep.signature.Recv().Pos())
			panic(fmt.Errorf("%s: failed to generate endpoint: %w", pos, err))
		}
		w.L("goto matched")
	})
	w.L("  // No match but we don't return a 404 here, to allow the default handler to take control.")
	w.L("  return")
	w.L("matched:")
	w.L("")
	w.L("// Handle errors")
	w.L("if err != nil {")
	w.L("  if herr, ok := err.(http.Handler); ok {")
	w.L("    herr.ServeHTTP(w, r)")
	w.L("  } else {")
	w.L("		 http.Error(w, err.Error(), http.StatusInternalServerError)")
	w.L("  }")
	w.L("  return")
	w.L("}")
	w.L("")
	w.L("// Handle response")
	w.L("switch res := res.(type) {")
	w.L("case nil:")
	w.L("  w.WriteHeader(http.StatusNoContent)")
	w.L("case string:")
	w.L("  w.Header().Set(\"Content-Type\", \"text/html\")")
	w.L("  io.WriteString(w, res)")
	w.L("case []byte:")
	w.L("  w.Header().Set(\"Content-Type\", \"application/octet-stream\")")
	w.L("  w.Write(res)")
	w.L("case *http.Response:")
	w.L("  headers := w.Header()")
	w.L("  for k, v := range res.Header {")
	w.L("    headers[k] = v")
	w.L("  }")
	w.L("  w.WriteHeader(res.StatusCode)")
	w.L("  _, _ = io.Copy(w, res.Body)")
	w.L("case io.ReadCloser:")
	w.L("  w.Header().Set(\"Content-Type\", \"application/octet-stream\")")
	w.L("  _, _ = io.Copy(w, res)")
	w.L("  res.Close()")
	w.L("case io.Reader:")
	w.L("  w.Header().Set(\"Content-Type\", \"application/octet-stream\")")
	w.L("  _, _ = io.Copy(w, res)")
	w.L("default:")
	w.In(func(w *codewriter.Writer) {
		w.L("data, err := json.Marshal(res)")
		w.L("if err != nil {")
		w.L("  http.Error(w, `failed to encode response: ` + err.Error(), http.StatusInternalServerError)")
		w.L("  return")
		w.L("}")
		w.L("w.Header().Set(\"Content-Type\", \"application/json\")")
		w.L("w.Header().Set(\"Content-Length\", strconv.Itoa(len(data)))")
		w.L("w.WriteHeader(http.StatusOK)")
		w.L("w.Write(data)")
	})
	w.L("}")
	w = w.Pop()
	w.L("}")
}

//nolint:nakedret
func extractEndpoints(pkg *packages.Package) (outPath string, endpoints map[string][]endpoint, retErr error) {
	endpoints = map[string][]endpoint{}
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			fn, ok := node.(*ast.FuncDecl)
			if !ok || fn.Doc == nil {
				return true
			}
			for _, line := range fn.Doc.List {
				if strings.HasPrefix(line.Text, "//happy:api") {
					pos := pkg.Fset.Position(fn.Pos())
					dir, err := parseDirective(fn.Doc.Text(), line.Text)
					if err != nil {
						retErr = fmt.Errorf("%s: %w", pos, err)
						return false
					}
					fnt := pkg.TypesInfo.Defs[fn.Name].(*types.Func)
					sig := fnt.Type().(*types.Signature)
					receiverName := sig.Recv().Type().String()
					endpoints[receiverName] = append(endpoints[receiverName], endpoint{
						decl:      fn,
						fn:        fnt,
						signature: sig,
						directive: dir,
					})
				}
			}
			return true
		})
		if retErr != nil {
			return
		}
		if outPath == "" && len(endpoints) > 0 {
			f := pkg.Fset.File(file.Pos())
			outPath = strings.TrimSuffix(f.Name(), ".go") + "_api.go"
		}
	}
	return
}

var nameExtract = regexp.MustCompile(`/:([a-zA-Z0-9]+)`)

// <method> <path> [<option>[=<value>] ...]
func parseDirective(doc, comment string) (directive, error) {
	parts := strings.Fields(comment)
	if len(parts) < 3 {
		return directive{}, fmt.Errorf("invalid directive, must be in the form //api:http <method> <url> [<option>=<value> ...]: %s", comment)
	}
	pattern := parts[2]
	matches := nameExtract.FindAllStringSubmatchIndex(pattern, -1)
	dir := directive{
		doc:     doc,
		method:  parts[1],
		pattern: pattern,
		options: map[string]string{},
	}
	for _, parami := range matches {
		param := pattern[parami[2]:parami[3]]
		dir.pathParams = append(dir.pathParams, param)
	}

	for _, option := range parts[3:] {
		parts := strings.SplitN(option, "=", 2)
		var value string
		if len(parts) == 2 {
			value = parts[1]
		}
		dir.options[parts[0]] = value
	}
	return dir, nil
}

func once[T any](f func() T) func() T {
	var once sync.Once
	var t T
	return func() T {
		once.Do(func() {
			t = f()
		})
		return t
	}
}

// Lazy load the compile-time type from a package.
func mustLoadInterface(pkg, name string) func() *types.Interface {
	return once[*types.Interface](func() *types.Interface {
		pkgs, err := packages.Load(&packages.Config{Fset: fset, Mode: packages.NeedTypes}, pkg)
		if err != nil {
			panic(err)
		}
		if len(pkgs) != 1 {
			panic("expected one package")
		}
		iface := pkgs[0].Types.Scope().Lookup(name)
		if iface == nil {
			panic("interface not found")
		}
		return iface.Type().Underlying().(*types.Interface)
	})
}

// Generate a function for decoding url.Values directly into a struct.
//
// Only a limited set of types are currently supported, and embedded structs are not supported.
func genQueryDecoderFunc(gctx *genContext, paramType types.Type) (name string, err error) {
	strct, ok := paramType.Underlying().(*types.Struct)
	if !ok {
		return "", fmt.Errorf("parameter must be a struct but is %s", paramType)
	}
	gctx.Import("net/url")
	_, typeRef := gctx.TypeRef(paramType)
	name = "decode" + ucFirst(strings.ReplaceAll(typeRef, ".", ""))
	w := gctx.Trailer()
	w.L("func %s(p url.Values, out *%s) (err error) {", name, typeRef)
	w = w.Push()
	for i := 0; i < strct.NumFields(); i++ {
		field := strct.Field(i)
		tags, err := structtag.Parse(strct.Tag(i))
		if err != nil {
			return "", fmt.Errorf("invalid struct tag on %s.%s: %w", typeRef, field.Name(), err)
		}
		fieldName := lcFirst(field.Name())
		if tag, err := tags.Get("query"); err == nil {
			fieldName = tag.Name
		}
		w.L("if q, ok := p[%q]; ok {", fieldName)
		w = w.Push()
		fieldType := field.Type()
		strctRef := "out"
		if _, ptr := fieldType.(*types.Pointer); ptr {
			fieldType = fieldType.(*types.Pointer).Elem()
			w.L("out.%s = new(%s)", field.Name(), fieldType)
			strctRef = "*" + strctRef
		}
		switch fieldType.String() {
		case "bool":
			gctx.Import("strconv")
			w.L("if %s.%s, err = strconv.ParseBool(q[len(q)-1]); err != nil {", strctRef, field.Name())
			w.L(`  return fmt.Errorf("failed to decode query parameter \"%s\" as %s: %%w", err)`, fieldName, fieldType)
			w.L("}")
		case "int":
			gctx.Import("strconv")
			w.L("if %s.%s, err = strconv.Atoi(q[len(q)-1]); err != nil {", strctRef, field.Name())
			w.L(`  return fmt.Errorf("failed to decode query parameter \"%s\" as %s: %%w", err)`, fieldName, fieldType)
			w.L("}")
		case "string":
			w.L("%s.%s = q[len(q)-1]", strctRef, field.Name())
		default:
			return "", fmt.Errorf("can't decode query parameter into field %s.%s of type %s, only int, string and bool are supported", paramType, field.Name(), field.Type())
		}
		w = w.Pop()
		w.L("}")
	}
	w.L("return nil")
	w = w.Pop()
	w.L("}")
	return name, nil
}

func ucFirst(s string) string {
	rn, n := utf8.DecodeRuneInString(s)
	return strings.ToUpper(string(rn)) + s[n:]
}

func lcFirst(s string) string {
	rn, n := utf8.DecodeRuneInString(s)
	return strings.ToLower(string(rn)) + s[n:]
}

type genContext struct {
	pkg *packages.Package
	*codewriter.Writer
}

func (g *genContext) Pos(pos token.Pos) token.Position {
	return g.pkg.Fset.Position(pos)
}

func (g *genContext) TypeRef(t types.Type) (pkgRef, ref string) {
	if named, ok := t.(*types.Named); ok {
		pkgRef = named.Obj().Pkg().Path()
		ref = named.Obj().Name()
		if pkgRef == g.pkg.PkgPath {
			pkgRef = ""
		} else {
			ref = path.Base(pkgRef) + "." + ref
		}
		return
	}
	return "", t.String()
}

func genEndpoint(gctx *genContext, w *codewriter.Writer, ep endpoint) error {
	params := ep.signature.Params()
	isParam := map[string]bool{}
	for i := 0; i < params.Len(); i++ {
		isParam[params.At(i).Name()] = true
	}

	isGroup := map[string]int{}
	for i, param := range ep.directive.pathParams {
		isGroup[param] = i + 1
	}

	args := []string{}
	for i := 0; i < params.Len(); i++ {
		param := params.At(i)
		pos := gctx.Pos(param.Pos())
		tn := param.Type().String()
		switch {
		case tn == "context.Context":
			args = append(args, "r.Context()")

		case tn == "net/http.ResponseWriter":
			args = append(args, "w")
			gctx.Import("net/http")

		case tn == "io.Reader":
			args = append(args, "r.Body")

		case tn == "*net/http.Request":
			args = append(args, "r")
			gctx.Import("net/http")

		case isGroup[param.Name()] != 0:
			index := isGroup[param.Name()] - 1
			pkgRef, ref := gctx.TypeRef(param.Type())
			if pkgRef != "" {
				gctx.Import(pkgRef)
			}
			bt := param.Type().Underlying().String()
			// Type aliases (eg. type Foo int) are supported if they alias
			// string or int, or implement encoding.TextUnmarshaler.
			switch {
			case implements(param, textUnmarshalerInterface()):
				paramName := fmt.Sprintf("param%d", index)
				w.L("var %s %s", paramName, ref)
				w.L("if err := %s.UnmarshalText([]byte(params[%d])); err != nil {", paramName, index)
				w.L("  http.Error(w, \"%s: \" + err.Error(), http.StatusBadRequest)", param.Name())
				w.L("  return")
				w.L("}")
				args = append(args, paramName)

			case bt == "string":
				if bt != ref {
					args = append(args, fmt.Sprintf("%s(params[%d])", ref, index))
				} else {
					args = append(args, fmt.Sprintf("params[%d]", index))
				}

			case bt == "int":
				paramName := fmt.Sprintf("param%d", index)
				w.L("var %s int", paramName)
				w.L("%s, err = strconv.Atoi(params[%d])", paramName, index)
				if bt != ref {
					args = append(args, fmt.Sprintf("%s(%s)", ref, paramName))
				} else {
					args = append(args, paramName)
				}
				w.L("if err != nil {")
				w.L("  http.Error(w, \"%s: \" + err.Error(), http.StatusBadRequest)", param.Name())
				w.L("  return")
				w.L("}")

			default:
				return fmt.Errorf("%s: %s: unsupported named parameter type %q", pos, param.Name(), param.Type())
			}

		// Not a parameter, so it must be a request body or query parameters.
		default: // TODO(aat): Handle pointers.
			paramType, ok := param.Type().(*types.Named)
			if !ok {
				return fmt.Errorf("%s: parameter %q does not map to any URL path variables and is of type %q, but must be a struct to be used as a request payload", pos, param.Name(), param.Type())
			}
			pkgRef, ref := gctx.TypeRef(param.Type())
			gctx.Import(pkgRef)

			w.L("var param%d %s", i, ref)
			gctx.Import("net/http")
			if ep.directive.method == http.MethodGet || ep.directive.method == http.MethodDelete {
				decoderFn, err := genQueryDecoderFunc(gctx, paramType)
				if err != nil {
					return fmt.Errorf("%s: %w", pos, err)
				}
				w.L("if err := %s(r.URL.Query(), &param%d); err != nil {", decoderFn, i)
				w.L(`  http.Error(w, fmt.Sprintf("Failed to decode query parameters: %%s", err), http.StatusBadRequest)`)
				w.L("  return")
				w.L("}")
			} else {
				gctx.Import("encoding/json")
				gctx.Import("fmt")
				w.L("if err := json.NewDecoder(r.Body).Decode(&param%d); err != nil {", i)
				w.L("  http.Error(w, fmt.Sprintf(\"Failed to decode request body: %%s\", err), http.StatusBadRequest)")
				w.L("  return")
				w.L("}")
			}
			args = append(args, fmt.Sprintf("param%d", i))
		}
	}
	results := ep.signature.Results()
	switch results.Len() {
	case 0:
	case 2:
		w.W("  res, err = ")
		pos := gctx.Pos(results.At(0).Pos())
		resType := results.At(0).Type()
		switch resType.String() {
		case "string", "[]byte", "*net/http.Response":
		default:
			switch resType.(type) {
			case *types.Named, *types.Slice, *types.Map:
			default:
				return fmt.Errorf("%s: unsupported return type %s", pos, results.At(0).Type())
			}
		}
	case 1:
		if results.At(0).Type().String() == "error" {
			w.W("  err = ")
			break
		}
		fallthrough
	default:
		return fmt.Errorf("%s: handler return values must be in the form (error) or (T, error)", ep.fn.Name())
	}
	w.L("h.%s(%s)", ep.fn.Name(), strings.Join(args, ", "))
	if results.Len() == 0 {
		w.L("return")
	}
	return nil
}

// A tree of path components mapping to endpoints.
type tree struct {
	part      string
	children  []tree
	endpoints []endpoint
}

func (t *tree) String() string {
	if len(t.children) == 0 {
		return fmt.Sprintf("/%s(%d)", t.part, len(t.endpoints))
	}
	childStrings := []string{}
	for _, child := range t.children {
		childStrings = append(childStrings, child.String())
	}
	return fmt.Sprintf("/%s(%d)[%s]", t.part, len(t.endpoints), strings.Join(childStrings, ", "))
}

func (t *tree) Write(w *codewriter.Writer, earlyExit string, visitor func(w *codewriter.Writer, endpoint endpoint)) {
	w.Import("strings")
	w.L(`parts := strings.Split(r.URL.Path, "/")`)
	w.L(`var params []string`)
	w.L(`_ = params`)
	w.L(`switch parts[0] {`)
	t.recursiveWrite(w, 0, visitor, earlyExit)
	w.L(`}`)
}

func (t *tree) recursiveWrite(w *codewriter.Writer, n int, visitor func(w *codewriter.Writer, endpoint endpoint), earlyExit string) {
	// Check if we want to match more path components but we've run out.
	// Variable path component always matches.
	if !strings.HasPrefix(t.part, ":") {
		w.L(`case "%s":`, t.part)
	} else {
		w.L(`default: // Parameter %s`, t.part)
		w.L(`  params = append(params, parts[%d])`, n)
	}
	w.In(func(w *codewriter.Writer) {
		w.In(func(w *codewriter.Writer) {
			w.L(`if len(parts) == %d {`, n+1)
			w.In(func(w *codewriter.Writer) {
				if len(t.endpoints) > 0 {
					w.L(`switch r.Method { // Leaf`)
					for _, endpoint := range t.endpoints {
						w.L(`case "%s":`, endpoint.directive.method)
						w.In(func(w *codewriter.Writer) {
							visitor(w, endpoint) //nolint:scopelint
						})
					}
					w.L(`}`)
				}
				w.L(`%s`, earlyExit)
			})
			w.L(`}`)
			if len(t.children) != 0 {
				w.L(`switch parts[%d] {`, n+1)
				for _, child := range t.children {
					child.recursiveWrite(w, n+1, visitor, earlyExit)
				}
				w.L(`}`)
			} else {
				w.L(`%s`, earlyExit)
			}
		})
	})
}

func makeTree(endpoints []endpoint) *tree {
	out := &tree{}
	for _, endpoint := range endpoints {
		updateTree(out, endpoint, strings.Split(endpoint.directive.pattern, "/"))
	}
	return out
}

func updateTree(out *tree, endpoint endpoint, path []string) {
	if len(path) == 0 || (path[0] == out.part && len(path) == 1) {
		out.endpoints = append(out.endpoints, endpoint)
		return
	}
	if path[0] == out.part {
		path = path[1:]
	}
	part := path[0]
	for i, child := range out.children {
		if child.part == part {
			updateTree(&out.children[i], endpoint, path[1:])
			return
		}
	}
	out.children = append(out.children, tree{part: part})
	updateTree(&out.children[len(out.children)-1], endpoint, path[1:])
}

func implements(v *types.Var, iface *types.Interface) bool {
	return types.Implements(v.Type(), iface) || types.Implements(types.NewPointer(v.Type()), iface)
}
