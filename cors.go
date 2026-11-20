package middleware

import (
	"github.com/rs/cors"
)

func (mw *Middleware) SetupCORS() *cors.Cors {
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   mw.cors.AllowedOrigins,
		AllowedMethods:   mw.cors.AllowedMethods,
		AllowedHeaders:   mw.cors.AllowedHeaders,
		ExposedHeaders:   mw.cors.ExposedHeaders,
		AllowCredentials: mw.cors.AllowCredentials,
		MaxAge:           mw.cors.MaxAge,
	})

	return corsMiddleware
}
