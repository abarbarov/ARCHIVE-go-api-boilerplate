package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth_chi"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"go.uber.org/zap"
	"hash/crc64"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
)

type Router struct {
	Logger        *zap.Logger
	Authenticator *Authenticator
	AppRoot       string
}

func (r *Router) NewRouter(name, version, secret string) chi.Router {
	router := chi.NewRouter()
	router.Use(middleware.RealIP, recoverer(r.Logger))
	router.Use(middleware.Throttle(1000), middleware.Timeout(60*time.Second))
	router.Use(appInfo(name, version), ping)

	ipFn := func(ip string) string { return hashValue(ip, secret)[:12] } // logger uses it for anonymization

	router.With(tollbooth_chi.LimitHandler(tollbooth.NewLimiter(50, nil))).
		Get("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
			allowed := []string{"/home"}
			for i := range allowed {
				allowed[i] = "Allow: " + allowed[i]
			}
			render.PlainText(w, r, "User-agent: *\nDisallow: /login/\nDisallow: /api/\n"+strings.Join(allowed, "\n")+"\n")
		})

	// api routes
	router.Route("/api/v1", func(rapi chi.Router) {
		rapi.Use(tollbooth_chi.LimitHandler(tollbooth.NewLimiter(50, nil)))

		// open routes
		rapi.Group(func(ropen chi.Router) {
			ropen.Use(r.Authenticator.Auth(false))
			ropen.Use(logger(r.Logger, ipFn, LogAll))

			ropen.Post("/public", r.PublicCtrl)
		})

		// protected routes, require auth
		rapi.Group(func(rauth chi.Router) {
			rauth.Use(r.Authenticator.Auth(true))
			rauth.Use(logger(r.Logger, ipFn, LogAll))

			rauth.Get("/private", r.PrivateCtrl)
		})
	})

	router.Route("/", func(rс chi.Router) {
		rс.Use(tollbooth_chi.LimitHandler(tollbooth.NewLimiter(10, nil)))
		rс.Use(middleware.Compress(-1, "text/plain", "text/javascript", "application/javascript", "application/json"))

		rс.Get("/img*", r.staticHandler)
		rс.Get("/css*", r.staticHandler)
		rс.Get("/js*", r.staticHandler)
		rс.Get("/favicon*", r.staticHandler)
		rс.Get("/*", r.clientPage("index.html"))
	})

	return router
}

func recoverer(logger *zap.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rvr := recover(); rvr != nil {
					logger.Warn("request panic", zap.String("err", fmt.Sprintf("%v", rvr)))
					debug.PrintStack()
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func appInfo(name, version string) func(http.Handler) http.Handler {
	f := func(h http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("App-Name", name)
			w.Header().Set("App-Version", version)
			h.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
	return f
}

func ping(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {

		if r.Method == "GET" && strings.HasSuffix(strings.ToLower(r.URL.Path), "/ping") {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("pong")); err != nil {
				log.Printf("[WARN] can't send pong, %s", err)
			}
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

var reValidSha = regexp.MustCompile("^[a-fA-F0-9]{40}$")

func hashValue(val string, secret string) string {
	if val == "" || reValidSha.MatchString(val) {
		return val // already hashed or empty
	}
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	if _, err := io.WriteString(h, val); err != nil {
		// fail back to crc64
		log.Printf("[WARN] can't hash ip, %s", err)
		return fmt.Sprintf("%x", crc64.Checksum([]byte(val), crc64.MakeTable(crc64.ECMA)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// LoggerFlag type
type LoggerFlag int

// logger flags enum
const (
	LogAll LoggerFlag = iota
	LogUser
	LogBody
	LogNone
)

const maxBody = 4096

var reMultWhtsp = regexp.MustCompile(`[\s\p{Zs}]{2,}`)

func inLogFlags(f LoggerFlag, flags []LoggerFlag) bool {
	for _, flg := range flags {
		if (flg == LogAll && f != LogNone) || flg == f {
			return true
		}
	}
	return false
}

func getBodyAndUser(r *http.Request, flags []LoggerFlag) (body string, user string) {
	ctx := r.Context()
	if ctx == nil {
		return "", ""
	}

	if inLogFlags(LogBody, flags) {
		if content, err := ioutil.ReadAll(r.Body); err == nil {
			body = string(content)
			r.Body = ioutil.NopCloser(bytes.NewReader(content))

			if len(body) > 0 {
				body = strings.Replace(body, "\n", " ", -1)
				body = reMultWhtsp.ReplaceAllString(body, " ")
			}

			if len(body) > maxBody {
				body = body[:maxBody] + "..."
			}
		}
	}

	if inLogFlags(LogUser, flags) {
		// TODO:
	}

	return body, user
}

func logger(logger *zap.Logger, ipFn func(ip string) string, flags ...LoggerFlag) func(http.Handler) http.Handler {

	f := func(h http.Handler) http.Handler {

		fn := func(w http.ResponseWriter, r *http.Request) {

			if inLogFlags(LogNone, flags) { // skip logging
				h.ServeHTTP(w, r)
				return
			}

			ww := middleware.NewWrapResponseWriter(w, 1)
			body, user := getBodyAndUser(r, flags)
			t1 := time.Now()
			defer func() {
				t2 := time.Now()

				q := r.URL.String()
				if qun, err := url.QueryUnescape(q); err == nil {
					q = qun
				}

				remoteIP := strings.Split(r.RemoteAddr, ":")[0]
				if strings.HasPrefix(r.RemoteAddr, "[") {
					remoteIP = strings.Split(r.RemoteAddr, "]:")[0] + "]"
				}
				if ipFn != nil {
					remoteIP = ipFn(remoteIP)
				}

				logger.Info("API CALL",
					zap.String("method", r.Method),
					zap.String("url", q),
					zap.String("remoteIP", remoteIP),
					zap.Int("status", ww.Status()),
					zap.Int("written", ww.BytesWritten()),
					zap.String("elapsed", t2.Sub(t1).String()),
					zap.String("user", user),
					zap.String("body", body),
				)
			}()

			h.ServeHTTP(ww, r)
		}
		return http.HandlerFunc(fn)
	}

	return f
}

func (r *Router) clientPage(file string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		http.ServeFile(w, req, r.AppRoot+"/assets/"+file)
	}
}

func (r *Router) staticHandler(w http.ResponseWriter, req *http.Request) {
	http.ServeFile(w, req, r.AppRoot+"/assets/"+req.URL.Path[1:])
}

func (r *Router) PublicCtrl(w http.ResponseWriter, req *http.Request) {
	render.Status(req, http.StatusOK)
	render.JSON(w, req, "PUBLIC")
}

func (r *Router) PrivateCtrl(w http.ResponseWriter, req *http.Request) {
	render.Status(req, http.StatusOK)
	render.JSON(w, req, "PRIVATE")
}
