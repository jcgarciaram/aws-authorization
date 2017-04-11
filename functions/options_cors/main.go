package main

import (
	"encoding/json"
	"github.com/apex/go-apex"
)


type Response struct  {
    StatusCode      string              `json:"statusCode"`
    Headers         map[string]string   `json:"headers"`
    Body            string              `json:"body"`
}


func main() {
	apex.HandleFunc(func(event json.RawMessage, ctx *apex.Context) (interface{}, error) {

        
        var r Response
        
        r.StatusCode = "200"
        r.Headers = map[string]string{
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE, HEAD",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Max-Age": "86400",
            "Access-Control-Allow-Headers":
            "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-XSRF-Token, X-HTTP-Method-Override, X-Requested-With",
        }
        
        // retJson, _ := json.Marshal(r)
        
        return r, nil
	})
}

