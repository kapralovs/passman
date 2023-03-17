package server

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/labstack/echo"
)

type App struct {
	router *echo.Echo
	server *http.Server
}

func NewApp() *App {
	return &App{}
}

func (a *App) Run() error {
	a.server = http.Server{
		Handler:        a.router,
		MaxHeaderBytes: 1 << 20,
		ReadTimout:     time.Second * 10,
		WriteTimeout:   time.Second * 10,
	}

	go func() {
		if err := a.server.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	quit := make(chan os.Signal, 1)

	signal.Notify(quit, os.Interrupt, os.Interrupt)

	<-quit

	ctx, shutdown := context.WithTimout(context.Background, time.Second*5)
	defer shutdown()

	return a.server.Shutdown(ctx)
}
