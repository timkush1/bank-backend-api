// package api_sec
package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET"))

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}


// Add this helper function
func HashPassword(password string) (string, error) {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(hashedPassword), err
}

// Update Register handler
func Register(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Hash the user's password
    hashedPassword, err := HashPassword(user.Password)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    user.Password = hashedPassword

    // Check for duplicate usernames
    for _, u := range users {
        if u.Username == user.Username {
            http.Error(w, "Username already exists", http.StatusConflict)
            return
        }
    }

    user.ID = len(users) + 1

    users = append(users, user)
	log.Printf("Users slice: %+v", users)
    json.NewEncoder(w).Encode(user)
}


// Add this helper function
func CheckPassword(hashedPassword, password string) error {
    return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}


// Update Login handler
func Login(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    var credentials User
    err := json.NewDecoder(r.Body).Decode(&credentials)
    if err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    for _, u := range users {
        if u.Username == credentials.Username {
            err := CheckPassword(u.Password, credentials.Password)
            if err != nil {
                http.Error(w, "Invalid credentials", http.StatusUnauthorized)
                return
            }

            // Create a token if credentials are valid for 15 minutes
            expirationTime := time.Now().Add(15 * time.Minute)
            claims := &Claims{
                Username: u.Username,
                Role:     u.Role,
                StandardClaims: jwt.StandardClaims{
                    ExpiresAt: expirationTime.Unix(),
                },
            }

            token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
            tokenString, err := token.SignedString(jwtKey)
            if err != nil {
                http.Error(w, "Internal server error", http.StatusInternalServerError)
                return
            }

            json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
            return
        }
    }
    http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

func AccountsHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	switch r.Method {
	case http.MethodPost:
		// Only admins can create accounts
		if claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		createAccount(w, r, claims)
	case http.MethodGet:
		// Only admins can list accounts
		if claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		listAccounts(w, r, claims)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}


func createAccount(w http.ResponseWriter, r *http.Request, claims *Claims) {
	var acc Account
	if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
		http.Error(w, "Invalid account data", http.StatusBadRequest)
		return
	}

	// Validate the user creating the account
	userExists := false
	for _, user := range users {
		if user.ID == acc.UserID { // Match against the provided userID (this is happening already after we have validated that an admin is creating an account)
			userExists = true
			if user.Role == "admin" {
				http.Error(w, "Accounts cannot be created for admin users", http.StatusForbidden) // Admins cannot have accounts, they just manage them!
				return
			}
			break
		}
	}
	if !userExists {
		http.Error(w, "User does not exist", http.StatusBadRequest)
		return
	}
	
	// Check if the user already has an account
	for _, existingAcc := range accounts {
		if existingAcc.UserID == acc.UserID {
			http.Error(w, "Account already exists for the user", http.StatusConflict)
			return
		}
	}


	// Assign userID and create account
	acc.ID = len(accounts) + 1
	acc.CreatedAt = time.Now()
	accounts = append(accounts, acc)

	log.Printf("Account created: %+v", acc) // Debug log
	json.NewEncoder(w).Encode(acc)
}


func listAccounts(w http.ResponseWriter, r *http.Request, claims *Claims) {
	json.NewEncoder(w).Encode(accounts)
}

func BalanceHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	switch r.Method {
	case http.MethodGet:
		getBalance(w, r, claims)
	case http.MethodPost:
		depositBalance(w, r, claims)
	case http.MethodDelete:
		withdrawBalance(w, r, claims)
	}
}

func getBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	
	//in the getBalance function,we let admins to get balance of every id, but users can only get their own balance!
	// Extract user_id from the query parameter
	userId := r.URL.Query().Get("user_id")

	// Validate user_id query parameter
	uid, err := strconv.Atoi(userId)
	if err != nil || uid <= 0 {
		http.Error(w, "Invalid or missing user_id", http.StatusBadRequest)
		return
	}

	// Check access permissions based on the user's role
	if claims.Role == "user" {
		// If the role is "user", ensure the user can only access their own account
		userFound := false
		for _, user := range users {
			if user.ID == uid && user.Username == claims.Username {
				userFound = true
				break
			}
		}
		if !userFound {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	} else if claims.Role == "admin" {
		log.Println("Admin access granted")
	} else {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Search for the account associated with the user_id
	for _, acc := range accounts {
		if acc.UserID == uid {
			json.NewEncoder(w).Encode(map[string]float64{"balance": acc.Balance})
			return
		}
	}

	http.Error(w, "Account not found", http.StatusNotFound)
}



func isUserAuthorized(claims *Claims, userID int) bool {
	for _, user := range users {
		if user.ID == userID && user.Username == claims.Username {
			return true
		}
	}
	return false
}


func depositBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	// in the depositBalance function, only users are able deposit to their own account!
	// we will restrict admins from depositing to any account! by checking for authorization for the exact user

	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Ensure the user is depositing to their own account
	if body.UserID <= 0 || !isUserAuthorized(claims, body.UserID) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	for i, acc := range accounts {
		if acc.UserID == body.UserID {
			accounts[i].Balance += body.Amount
			json.NewEncoder(w).Encode(accounts[i])
			return
		}
	}

	http.Error(w, "Account not found", http.StatusNotFound)
}

func withdrawBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	// in the withdrawBalance function, only users are able withdraw from their own account!
	// we will restrict admins from withdrawing from any account! by checking for authorization for the exact user
	
	
	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Ensure the user is withdrawing from their own account
	if body.UserID <= 0 || !isUserAuthorized(claims, body.UserID) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	for i, acc := range accounts {
		if acc.UserID == body.UserID {
			if acc.Balance < body.Amount {
				http.Error(w, ErrInsufficientFunds.Error(), http.StatusBadRequest)
				return
			}
			accounts[i].Balance -= body.Amount
			json.NewEncoder(w).Encode(accounts[i])
			return
		}
	}

	http.Error(w, "Account not found", http.StatusNotFound)
}


func Auth(next func(http.ResponseWriter, *http.Request, *Claims)) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        startTime := time.Now()

        // Wrap the ResponseWriter
        lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

        // Validate token and extract claims
        claims, err := validateToken(r)
        if err != nil {
            lrw.WriteHeader(http.StatusUnauthorized)
            logRequestResponse(r, lrw, startTime)
            http.Error(lrw, "Unauthorized", http.StatusUnauthorized)
            return
        }

        log.Printf("Authenticated user: %s with role: %s", claims.Username, claims.Role)

        next(lrw, r, claims)

        logRequestResponse(r, lrw, startTime)
    }
}



func validateToken(r *http.Request) (*Claims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("missing or invalid token")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid or expired token")
	}
	return claims, nil
}

func RoleMiddleware(requiredRole string, next func(http.ResponseWriter, *http.Request, *Claims)) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        startTime := time.Now()

        // Wrap the ResponseWriter
        lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

        // Validate token and extract claims
        claims, err := validateToken(r)
        if err != nil {
            lrw.WriteHeader(http.StatusUnauthorized)
            logRequestResponse(r, lrw, startTime)
            http.Error(lrw, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Check if the user's role matches the required role
        if claims.Role != requiredRole {
            lrw.WriteHeader(http.StatusForbidden)
            logRequestResponse(r, lrw, startTime)
            http.Error(lrw, "Forbidden", http.StatusForbidden)
            return
        }

        log.Printf("User %s passed role validation: required role %s", claims.Username, requiredRole)

        next(lrw, r, claims)

        logRequestResponse(r, lrw, startTime)
    }
}


type RequestLog struct {
	URL         string              `json:"url"`
	QSParams    map[string][]string `json:"qs_params"`
	Headers     http.Header         `json:"headers"`
	ReqBodyLen  int64               `json:"req_body_len"`
}

type ResponseLog struct {
	StatusClass  string `json:"status_class"`
	RspBodyLen   int `json:"rsp_body_len"`
}

type LogData struct {
	Req RequestLog  `json:"req"`
	Rsp ResponseLog `json:"rsp"`
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	body       []byte
}

func (lrw *loggingResponseWriter) WriteHeader(statusCode int) {
	lrw.statusCode = statusCode
	lrw.ResponseWriter.WriteHeader(statusCode)
}

func (lrw *loggingResponseWriter) Write(data []byte) (int, error) {
	// Capture the response body
	lrw.body = append(lrw.body, data...)
	return lrw.ResponseWriter.Write(data)
}

// i am adding startTime as an argument in case that in the future we want to log the time taken for each request for Bola attacks detection
func logRequestResponse(r *http.Request, lrw *loggingResponseWriter, startTime time.Time) {
	logFile, err := os.OpenFile("access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	

	// Prepare the log data
	logData := LogData{
		Req: RequestLog{
			URL:        r.URL.String(),
			QSParams:   r.URL.Query(),
			Headers:    r.Header,
			ReqBodyLen: r.ContentLength,
		},
		Rsp: ResponseLog{
			StatusClass: fmt.Sprintf("%dxx", lrw.statusCode/100),
			RspBodyLen:  len(lrw.body),
		},
	}

	// Serialize the log data to JSON
	logJSON, err := json.Marshal(logData)
	if err != nil {
		log.Printf("Failed to marshal log data: %v", err)
		return
	}

	// Write  log data to file
	if _, err := logFile.WriteString(fmt.Sprintf("%s\n", logJSON)); err != nil {
		log.Printf("Failed to write log to file: %v", err)
	}
}



