package handler

import (
	"encoding/json"
	"fmt"
	"jwtDeEnCode/model"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

const (
	SecretKey = "qwer!1234"
)

//驗證
func ValidateTokenMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SecretKey), nil
		})

	if err == nil {
		if token.Valid {
			next(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Token is not valid")
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Unauthorized access to this resource")
	}
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	GetTokenDecode(token, w)
}

func JsonResponse(response interface{}, w http.ResponseWriter) {

	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func GetTokenDecode(tokenString string, w http.ResponseWriter) {

	claims := jwt.MapClaims{}

	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {

		return []byte(SecretKey), nil
	})

	if err != nil {
		return
	}

	JsonResponse(claims, w)

}

// 將傳入資料 雜湊成JWT Token
func Encode(w http.ResponseWriter, r *http.Request) {

	var user model.UserCredentials

	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Error in request")
		return
	}

	//request 的簡單判斷
	if strings.ToLower(user.Username) != "someone" {
		if user.Password != "[email protected]" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Println("Error logging in")
			fmt.Fprint(w, "Invalid credentials")
			return
		}
	}

	///這邊做jwt的雜湊
	token := jwt.New(jwt.SigningMethodHS256)
	claims := make(jwt.MapClaims)

	/// 資料
	claims["user_name"] = user.Username
	claims["user_id"] = "AAA123"
	claims["time"] = time.Now().Unix()
	claims["pwd"] = user.Password

	token.Claims = claims

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error extracting the key")
		fatal(err)
	}

	tokenString, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error while signing the token")
		fatal(err)
	}

	response := model.Token{tokenString}
	JsonResponse(response, w)

}
