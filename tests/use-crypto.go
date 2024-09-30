// copyright : Copyright (c) 2023-2024 Red Hat
// license   : GNU GFDL v1.3; see accompanying LICENSE file.

// The following is a minimal TLS server which, once compiled,
// will contain references to crypto symbols. 
package main

import (
  	"fmt"
  	"net/http"
)

func printHello(w http.ResponseWriter, req *http.Request) {
  fmt.Fprintf(w, "Hello From Server!")
}

func main() {
  srv := http.Server{Addr: ":3000", Handler: http.HandlerFunc(printHello)}
  srv.ListenAndServeTLS("server.crt", "server.key")
}
