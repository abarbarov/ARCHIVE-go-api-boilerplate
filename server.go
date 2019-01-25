package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-openapi/runtime/flagext"
	"github.com/go-openapi/swag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-chi/chi"
	"golang.org/x/net/netutil"
)

func NewServer() *Server {
	s := new(Server)

	s.shutdown = make(chan struct{})
	s.interrupt = make(chan os.Signal, 1)
	return s
}

// ConfigureAPI configures the API and handlers.
func (s *Server) ConfigureAPI(version, appRoot string) {
	if s.router == nil {
		router := Router{
			AppRoot:       appRoot,
			Authenticator: nil,
			Logger:        s.Logger,
		}

		s.router = router.NewRouter(s.Name, version, s.SecretKey)
	}
}

func (s *Server) ConfigureLogger() {
	if s.Logger == nil {
		s.Logger = newLogger(s.LogsPath)
	}
}

type Server struct {
	EnabledListeners []string         `long:"scheme" description:"the listeners to enable, this can be repeated and defaults to the schemes in the swagger spec"`
	CleanupTimeout   time.Duration    `long:"cleanup-timeout" description:"grace period for which to wait before killing idle connections" default:"10s"`
	GracefulTimeout  time.Duration    `long:"graceful-timeout" description:"grace period for which to wait before shutting down the server" default:"15s"`
	MaxHeaderSize    flagext.ByteSize `long:"max-header-size" description:"controls the maximum number of bytes the server will read parsing the request header's keys and values, including the request line. It does not limit the size of the request body." default:"1MiB"`

	SecretKey        string `long:"secret" env:"SECRET" required:"true" default:"SU7stRLaHaJhKJJecPVShYHwND5zJzK4vE5Ds1fP" description:"secret key"`
	Name             string `long:"appname" env:"APPNAME" required:"true" default:"unknown" description:"app name"`
	Environment      string `long:"env" env:"ENV" required:"true" default:"dev" description:"environment mode"`
	DataRoot         string `long:"data-root" env:"DATA_ROOT" default:"/apps/unknown/data" description:"app data location"`
	LogsPath         string `long:"logs-path" env:"APP_LOGS_PATH" default:"app.log" description:"app logs location"`
	ConnectionString string `long:"connection-string-main" env:"CONNECTION_MAIN" default:"" description:"database connection string"`

	Host         string        `long:"host" description:"the IP to listen on" default:"localhost" env:"HOST"`
	Port         int           `long:"port" description:"the port to listen on for insecure connections, defaults to a random value" env:"PORT" default:"10111"`
	ListenLimit  int           `long:"listen-limit" description:"limit the number of outstanding requests"`
	KeepAlive    time.Duration `long:"keep-alive" description:"sets the TCP keep-alive timeouts on accepted connections. It prunes dead TCP connections ( e.g. closing laptop mid-download)" default:"3m"`
	ReadTimeout  time.Duration `long:"read-timeout" description:"maximum duration before timing out read of the request" default:"30s"`
	WriteTimeout time.Duration `long:"write-timeout" description:"maximum duration before timing out write of the response" default:"60s"`
	httpServer   net.Listener
	router       chi.Router
	hasListeners bool
	shutdown     chan struct{}
	shuttingDown int32
	interrupted  bool
	interrupt    chan os.Signal
	Logger       *zap.Logger
}

// Logf logs message either via defined user logger or via system one if no user logger is defined.
func (s *Server) Logf(f string, args ...zap.Field) {
	if s.Logger != nil {
		s.Logger.Info(f, args...)
	} else {
		fields := make([]interface{}, len(args))
		for i, d := range args {
			fields[i] = d.String
		}

		log.Printf(f, fields...)
	}
}

// Fatalf logs message either via defined user logger or via system one if no user logger is defined.
// Exits with non-zero status after printing
func (s *Server) Fatalf(f string, args ...zap.Field) {
	if s.Logger != nil {
		s.Logger.Fatal(f, args...)
		os.Exit(1)
	} else {
		fields := make([]interface{}, len(args))
		for i, d := range args {
			fields[i] = d.String
		}
		log.Fatalf(f, fields...)
	}
}

func newLogger(path string) *zap.Logger {
	highPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapcore.ErrorLevel
	})
	lowPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl < zapcore.ErrorLevel
	})
	topicDebugging := zapcore.AddSync(ioutil.Discard)
	topicErrors := zapcore.AddSync(ioutil.Discard)
	rolling := zapcore.AddSync(&lumberjack.Logger{
		Filename:   path,
		MaxSize:    100, // megabytes
		MaxBackups: 3,
		MaxAge:     30, // days
	})
	consoleDebugging := zapcore.Lock(os.Stdout)
	consoleErrors := zapcore.Lock(os.Stderr)
	errorEncoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	consoleEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	core := zapcore.NewTee(
		zapcore.NewCore(errorEncoder, topicErrors, highPriority),
		zapcore.NewCore(consoleEncoder, consoleErrors, highPriority),
		zapcore.NewCore(errorEncoder, topicDebugging, lowPriority),
		zapcore.NewCore(consoleEncoder, consoleDebugging, lowPriority),

		zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), rolling, zap.InfoLevel),
	)
	logger := zap.New(core)
	return logger
}

// Serve the api
func (s *Server) Serve() (err error) {
	if !s.hasListeners {
		if err = s.Listen(); err != nil {
			return err
		}
	}

	// set default handler, if none is set
	if s.router == nil {
		return errors.New("can't create the default handler, as no api is set")
	}

	wg := new(sync.WaitGroup)
	once := new(sync.Once)
	signalNotify(s.interrupt)
	go handleInterrupt(once, s)

	var servers []*http.Server
	wg.Add(1)
	go s.handleShutdown(wg, &servers)

	httpServer := new(http.Server)
	httpServer.MaxHeaderBytes = int(s.MaxHeaderSize)
	httpServer.ReadTimeout = s.ReadTimeout
	httpServer.WriteTimeout = s.WriteTimeout
	httpServer.SetKeepAlivesEnabled(int64(s.KeepAlive) > 0)
	if s.ListenLimit > 0 {
		s.httpServer = netutil.LimitListener(s.httpServer, s.ListenLimit)
	}

	if int64(s.CleanupTimeout) > 0 {
		httpServer.IdleTimeout = s.CleanupTimeout
	}

	httpServer.Handler = s.router

	servers = append(servers, httpServer)
	wg.Add(1)
	s.Logf("Serving app at", zap.String("Addr", fmt.Sprintf("%s", s.httpServer.Addr())))
	go func(l net.Listener) {
		defer wg.Done()
		if err := httpServer.Serve(l); err != nil && err != http.ErrServerClosed {
			s.Fatalf("Failed to start", zap.Error(err))
		}
		s.Logf("Stopped serving app at", zap.String("Addr", fmt.Sprintf("%s", l.Addr())))
	}(s.httpServer)

	wg.Wait()
	return nil
}

// Listen creates the listeners for the server
func (s *Server) Listen() error {
	if s.hasListeners { // already done this
		return nil
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return err
	}

	h, p, err := swag.SplitHostPort(listener.Addr().String())
	if err != nil {
		return err
	}
	s.Host = h
	s.Port = p
	s.httpServer = listener

	s.hasListeners = true
	return nil
}

// Shutdown server and clean up resources
func (s *Server) Shutdown() error {
	if atomic.CompareAndSwapInt32(&s.shuttingDown, 0, 1) {
		if s.Logger != nil {
			_ = s.Logger.Sync()
		}
		close(s.shutdown)
	}
	return nil
}

func (s *Server) handleShutdown(wg *sync.WaitGroup, serversPtr *[]*http.Server) {
	// wg.Done must occur last, after s.api.ServerShutdown()
	// (to preserve old behaviour)
	defer wg.Done()

	<-s.shutdown

	servers := *serversPtr

	ctx, cancel := context.WithTimeout(context.TODO(), s.GracefulTimeout)
	defer cancel()

	shutdownChan := make(chan bool)
	for i := range servers {
		server := servers[i]
		go func() {
			var success bool
			defer func() {
				shutdownChan <- success
			}()
			if err := server.Shutdown(ctx); err != nil {
				// Error from closing listeners, or context timeout:
				s.Logf("HTTP server Shutdown", zap.Error(err))
			} else {
				success = true
			}
		}()
	}

	// Wait until all listeners have successfully shut down before calling ServerShutdown
	success := true
	for range servers {
		success = success && <-shutdownChan
	}

	if success {
		// TODO:
	}
}

// GetHandler returns a handler useful for testing
func (s *Server) GetHandler() http.Handler {
	return s.router
}

// HTTPListener returns the http listener
func (s *Server) HTTPListener() (net.Listener, error) {
	if !s.hasListeners {
		if err := s.Listen(); err != nil {
			return nil, err
		}
	}
	return s.httpServer, nil
}

func handleInterrupt(once *sync.Once, s *Server) {
	once.Do(func() {
		for range s.interrupt {
			if s.interrupted {
				s.Logf("Server already shutting down")
				continue
			}
			s.interrupted = true
			s.Logf("Shutting down... ")
			if err := s.Shutdown(); err != nil {
				s.Logf("HTTP server Shutdown", zap.Error(err))
			}
		}
	})
}

func signalNotify(interrupt chan<- os.Signal) {
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
}
