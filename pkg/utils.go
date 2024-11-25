package pkg

import (
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/dgrijalva/jwt-go"
)

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
