package main

import (
    jwt "github.com/dgrijalva/jwt-go"

    "github.com/apex/go-apex"
	"encoding/json"
    "strings"
    "errors"
    "log"
    "fmt"
    "os"

    // "github.com/aws/aws-sdk-go/service/iam"
)

var (
    secret = os.Getenv("AUTH0_CLIENT_SECRET")
)

type StatementStruct struct  {
    Effect      string  `json:"Effect"`
    Action      []string  `json:"Action"`
    Resource    []string  `json:"Resource"`
}

type AuthResponse struct {
    PrincipalId string  `json:"principalId"`
    PolicyDocument struct {
        Version     string  `json:"Version"`
        Statement     []StatementStruct `json:"Statement"`
    } `json:"policyDocument"`
}

func main() {
	apex.HandleFunc(func(event json.RawMessage, ctx *apex.Context) (interface{}, error) {
    
        var e interface{}
        _ = json.Unmarshal(event, &e)
    
        eventMap := e.(map[string]interface{})
        
        log.Println(eventMap)
        
        // If user is trying to log in, pass the request through
        methodArn := eventMap["methodArn"].(string)
        if strings.HasSuffix(methodArn, "/api/users/login") {
            return generatePolicy("Allow", eventMap), nil
        }
        
        // For any other request, get authorization token
        authToken := eventMap["authorizationToken"].(string)
        
        splitToken := strings.Split(authToken, " ")
        
        if len(splitToken) != 2 {
            return generatePolicy("Deny", eventMap), nil
        }
        
        ok := parseToken(splitToken[1])
        
        if ok {
            return generatePolicy("Allow", eventMap), nil
        } else {
            return generatePolicy("Deny", eventMap), nil
        } 
        
        return nil, errors.New("Unauthorized")
	})
}


func generatePolicy(effect string, eventMap map[string]interface{}) AuthResponse {

    resource := eventMap["methodArn"].(string)
    
    var authResponse AuthResponse
    
    authResponse.PrincipalId = "user"
    authResponse.PolicyDocument.Version = "2012-10-17" // default version
    authResponse.PolicyDocument.Statement = append(authResponse.PolicyDocument.Statement, StatementStruct{effect, []string{"execute-api:Invoke"}, []string{resource}});
    

    return authResponse
}

func parseToken(tokenString string) bool {

    // Parse takes the token string and a function for looking up the key. The latter is especially
    // useful if you use multiple keys for your application.  The standard is to use 'kid' in the
    // head of the token to identify which key to use, but the parsed token (head and claims) is provided
    // to the callback, providing flexibility.
    token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    
        // Don't forget to validate the alg is what you expect:
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
        }

        // secret is a []byte containing your secret, e.g. []byte("my_secret_key")
        return []byte(secret), nil
    })

    if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        return true
    } else {
        return false
    }
}