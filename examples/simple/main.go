// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
)

func main() {
	// turn on debug logging
	l := hclog.New(&hclog.LoggerOptions{
		Name:  "simple-bind-logger",
		Level: hclog.Debug,
	})

	// a very simple way to track authenticated connections
	authenticatedConnections := map[int]struct{}{}

	// create a new server
	s, err := gldap.NewServer(gldap.WithLogger(l), gldap.WithDisablePanicRecovery())
	if err != nil {
		log.Fatalf("unable to create server: %s", err.Error())
	}

	// create a router and add a bind handler
	r, err := gldap.NewMux()
	if err != nil {
		log.Fatalf("unable to create router: %s", err.Error())
	}
	r.Bind(bindHandler(authenticatedConnections))
	r.Search(searchHandler(authenticatedConnections), gldap.WithLabel("All Searches"))
	s.Router(r)
	go s.Run(":10389") // listen on port 10389

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	select {
	case <-ctx.Done():
		log.Printf("\nstopping directory")
		s.Stop()
	}
}

func bindHandler(authenticatedConnections map[int]struct{}) func(*gldap.ResponseWriter, *gldap.Request) {
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		resp := r.NewBindResponse(
			gldap.WithResponseCode(gldap.ResultInvalidCredentials),
		)
		defer func() {
			w.Write(resp)
		}()

		m, err := r.GetSimpleBindMessage()
		if err != nil {
			log.Printf("not a simple bind message: %s", err)
			return
		}
		if m.UserName == "uid=alice" {
			authenticatedConnections[r.ConnectionID()] = struct{}{} // mark connection as authenticated
			resp.SetResultCode(gldap.ResultSuccess)
			log.Println("bind success")
			return
		}
	}
}

func searchHandler(authenticatedConnections map[int]struct{}) func(w *gldap.ResponseWriter, r *gldap.Request) {
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		resp := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject))
		defer func() {
			w.Write(resp)
		}()
		// check if connection is authenticated
		if _, ok := authenticatedConnections[r.ConnectionID()]; !ok {
			log.Printf("connection %d is not authorized", r.ConnectionID())
			resp.SetResultCode(gldap.ResultAuthorizationDenied)
			return
		}
		m, err := r.GetSearchMessage()
		if err != nil {
			log.Printf("not a search message: %s", err)
			return
		}
		log.Printf("search base dn: %s", m.BaseDN)
		log.Printf("search scope: %d", m.Scope)
		log.Printf("search filter: %s", m.Filter)

		if strings.Contains(m.Filter, "uid=alice") || m.BaseDN == "uid=alice,ou=people,cn=example,dc=org" {
			entry := r.NewSearchResponseEntry(
				"uid=alice,ou=people,cn=example,dc=org",
				gldap.WithAttributes(map[string][]string{
					"objectclass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
					"uid":         {"alice"},
					"cn":          {"alice eve smith"},
					"givenname":   {"alice"},
					"sn":          {"smith"},
					"ou":          {"people"},
					"description": {"friend of Rivest, Shamir and Adleman"},
					"password":    {"{SSHA}U3waGJVC7MgXYc0YQe7xv7sSePuTP8zN"},
				}),
			)
			entry.AddAttribute("email", []string{"alice@example.org"})
			w.Write(entry)
			resp.SetResultCode(gldap.ResultSuccess)
		}
		if m.BaseDN == "ou=people,cn=example,dc=org" {
			entry := r.NewSearchResponseEntry(
				"ou=people,cn=example,dc=org",
				gldap.WithAttributes(map[string][]string{
					"objectclass": {"organizationalUnit"},
					"ou":          {"people"},
				}),
			)
			w.Write(entry)
			resp.SetResultCode(gldap.ResultSuccess)
		}
	}
}
