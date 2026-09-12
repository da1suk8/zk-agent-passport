// Command web serves a browser demo of zkAgent Passport. Every run executes
// the real protocol (receipts, gateway checks, secret sharing, certificate,
// Groth16 proof, verification) and returns a step-by-step trace that the
// page animates. No external assets are used, so it works offline.
//
// The package is split by concern: main.go boots the server and owns the
// state of the last run, api.go holds the HTTP handlers, trace.go turns a
// protocol run into the steps the page animates, attack.go builds the
// malicious receipts the page can submit, and text.go holds every string
// shown to the reader.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/consensys/gnark/logger"

	"github.com/da1suk8/zk-agent-passport/internal/demo"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

//go:embed index.html
var indexHTML []byte

// defaultAddr honours PORT so a supervisor can hand the demo a free port,
// and falls back to 8080 when nothing is set.
func defaultAddr() string {
	if p := os.Getenv("PORT"); p != "" {
		return "127.0.0.1:" + p
	}
	return "127.0.0.1:8080"
}

func main() {
	addr := flag.String("addr", defaultAddr(), "listen address")
	artifacts := flag.String("artifacts", "artifacts", "directory for cached Groth16 keys")
	flag.Parse()
	logger.Disable()

	sys, err := zkp.LoadOrSetup(*artifacts)
	if err != nil {
		log.Fatal(err)
	}
	s := &server{sys: sys}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /api/defaults", s.defaults)
	mux.HandleFunc("POST /api/run", s.run)
	mux.HandleFunc("POST /api/replay", s.replay)
	mux.HandleFunc("POST /api/attack", s.attack)
	mux.HandleFunc("POST /api/other-service", s.otherService)

	httpServer := &http.Server{Addr: *addr, Handler: mux}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	fmt.Printf("zkAgent Passport demo: http://%s  (constraints=%d)\n", *addr, sys.NbConstraints())
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

type server struct {
	sys  *zkp.System
	mu   sync.Mutex
	last *lastRun
}

type lastRun struct {
	world     *demo.World
	challenge passport.Challenge
	pkg       *passport.ProofPackage
}

// currentWorld returns the world of the last run, provisioning a default
// one if the page has not run yet.
func (s *server) currentWorld() (*demo.World, error) {
	if s.last != nil && s.last.world != nil {
		return s.last.world, nil
	}
	world, err := demo.NewWorld(s.sys)
	if err != nil {
		return nil, err
	}
	s.last = &lastRun{world: world}
	return world, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
