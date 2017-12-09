package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

func GetReverseProxy(url string) http.Handler {
	proxyUrl, err := url.Parse(url)
	if err != nil {
		panic(err)
	}
	return httputil.NewSingleHostReverseProxy(proxyUrl)
}
