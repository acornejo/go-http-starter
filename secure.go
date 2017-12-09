package main

import (
	"golang.org/x/crypto/acme/autocert"
	"net"
)

func GetSecureListener(domain string, email string, certsDir string) net.Listener {
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Email:      email,
		Cache:      autocert.DirCache(certsDir),
	}

	return certManager.Listener()
}
