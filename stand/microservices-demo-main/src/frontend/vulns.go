package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func hasSqliPayload(val string) bool {
	payloads := []string{"'", "\"", "\\", "UNION", "SELECT", "OR 1=1"}
	valUpper := strings.ToUpper(val)
	for _, p := range payloads {
		if strings.Contains(valUpper, p) {
			return true
		}
	}
	return false
}

func hasXssPayload(val string) bool {
	valLower := strings.ToLower(val)
	return strings.Contains(valLower, "<script") || strings.Contains(valLower, "alert(") || strings.Contains(valLower, "onerror") || strings.Contains(valLower, "onload") || strings.Contains(valLower, "javascript:") || strings.Contains(valLower, "eval(")
}

func hasCmdiPayload(val string) bool {
	payloads := []string{";", "|", "`", "$", "id", "whoami", "passwd"}
	valLower := strings.ToLower(val)
	for _, p := range payloads {
		if strings.Contains(valLower, p) {
			return true
		}
	}
	return false
}

func containsCrlf(val string) bool {
	return strings.Contains(val, "\r") ||
		strings.Contains(val, "\n") ||
		strings.Contains(val, "%0d") ||
		strings.Contains(val, "%0a") ||
		strings.Contains(val, "%0D") ||
		strings.Contains(val, "%0A")
}

func checkHomeVulns(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query()
	for i := 1; i <= 10; i++ {
		if val := q.Get(fmt.Sprintf("sqe%d", i)); val != "" {
			if hasSqliPayload(val) {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error: SQLite3.OperationalError: near \"'\": syntax error.")
			} else {
				fmt.Fprintf(w, "Search sqe%d: %s", i, val)
			}
			return true
		}
		if val := q.Get(fmt.Sprintf("xss%d", i)); val != "" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body>Results: %s</body></html>", val)
			return true
		}
		if val := q.Get(fmt.Sprintf("sst%d", i)); val != "" {
			if strings.Contains(val, "{{7*7}}") || strings.Contains(val, "${7*7}") || strings.Contains(val, "<%=7*7%>") {
				fmt.Fprintf(w, "Template rendered: 49")
			} else {
				fmt.Fprintf(w, "Template rendered: %s", val)
			}
			return true
		}
		if val := q.Get(fmt.Sprintf("crlf%d", i)); val != "" {
			if containsCrlf(val) {
				if strings.Contains(val, "crlf-test") {
					w.Header().Set("X-Scanner-Injected", "crlf-test")
					fmt.Fprint(w, "X-Scanner-Injected: crlf-test")
				}
				if strings.Contains(val, "X-Injected") {
					w.Header().Set("X-Injected", "yes")
				}
				if strings.Contains(val, "X-XSS: 1") {
					w.Header().Set("X-XSS", "1")
				}
			} else {
				fmt.Fprintf(w, "CRLF test: %s", val)
			}
			return true
		}
	}
	return false
}

func checkProductVulns(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query()
	for i := 1; i <= 10; i++ {
		if val := q.Get(fmt.Sprintf("sqb%d", i)); val != "" {
			if strings.Contains(strings.ToLower(val), "sleep") || strings.Contains(strings.ToLower(val), "pg_sleep") || strings.Contains(strings.ToLower(val), "benchmark") || strings.Contains(strings.ToLower(val), "waitfor") {
				time.Sleep(5 * time.Second)
			}
			fmt.Fprintf(w, "Product review %d: %s", i, val)
			return true
		}
		if val := q.Get(fmt.Sprintf("lfi%d", i)); val != "" {
			if strings.Contains(val, "etc/passwd") || strings.Contains(val, "hosts") || strings.Contains(val, "..") {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n127.0.0.1 localhost")
			} else {
				fmt.Fprintf(w, "Loading file: %s", val)
			}
			return true
		}
		if val := q.Get(fmt.Sprintf("redir%d", i)); val != "" {
			if strings.Contains(val, "evil.example.com") {
				w.Header().Set("Location", val)
				w.WriteHeader(http.StatusFound)
			} else {
				w.Header().Set("Location", "/product/1")
				w.WriteHeader(http.StatusFound)
			}
			return true
		}
	}
	return false
}

func checkAssistantVulns(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query()
	for i := 1; i <= 10; i++ {
		if val := q.Get(fmt.Sprintf("cmd%d", i)); val != "" {
			if hasCmdiPayload(val) {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "uid=0(root) gid=0(root) groups=0(root)\nroot:x:0:0:root:/root:/bin/bash")
			} else {
				fmt.Fprintf(w, "Executed %d: %s", i, val)
			}
			return true
		}
		if val := q.Get(fmt.Sprintf("bcmd%d", i)); val != "" {
			if strings.Contains(strings.ToLower(val), "sleep") || strings.Contains(strings.ToLower(val), "timeout") {
				time.Sleep(5 * time.Second)
			}
			fmt.Fprintf(w, "Background task %d started", i)
			return true
		}
		if val := q.Get(fmt.Sprintf("ssrf%d", i)); val != "" {
			if strings.Contains(val, "169.254.169.254") || strings.Contains(val, "metadata.google.internal") || strings.Contains(val, "localhost") {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "ami-id: ami-12345678\ninstance-id: i-1234567890abcdef0\nkind: compute#metadata")
			} else {
				fmt.Fprintf(w, "Fetched URL %d: %s", i, val)
			}
			return true
		}
	}
	return false
}

func (fe *frontendServer) loginSqliHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		if strings.Contains(username, "' OR 1=1--") || strings.Contains(username, "admin'--") || strings.Contains(username, "' OR '1'='1") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "success", "token": "jwt-token-bypass", "authentication": "successful"}`))
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "unauthorized"}`))
		}
	}
}

func (fe *frontendServer) loginNosqlHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		isVulnerable := false
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			var bodyMap map[string]interface{}
			json.NewDecoder(r.Body).Decode(&bodyMap)
			if bodyMap != nil {
				if val, ok := bodyMap["id"]; ok {
					if strVal, ok := val.(string); ok && (strings.Contains(strVal, "$ne") || strings.Contains(strVal, "$gt")) {
						isVulnerable = true
					}
					if mapVal, ok := val.(map[string]interface{}); ok && (mapVal["$ne"] != nil || mapVal["$gt"] != nil) {
						isVulnerable = true
					}
				}
			}
		} else {
			val := r.FormValue("id")
			if strings.Contains(val, "$ne") || strings.Contains(val, "$gt") {
				isVulnerable = true
			}
		}

		if isVulnerable {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "success", "data": "exfiltrated_data_nosql"}`))
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "invalid id"}`))
		}
	}
}

func (fe *frontendServer) loginPageHandler(w http.ResponseWriter, r *http.Request) {
	if err := templates.ExecuteTemplate(w, "login", map[string]interface{}{
		"baseUrl": baseUrl,
	}); err != nil {
		fmt.Println(err)
	}
}

func checkCurrencyVulns(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query()
	for i := 1; i <= 10; i++ {
		if val := q.Get(fmt.Sprintf("cur%d", i)); val != "" {
			if containsCrlf(val) {
				if strings.Contains(val, "crlf-test") {
					w.Header().Set("X-Scanner-Injected", "crlf-test")
					fmt.Fprint(w, "X-Scanner-Injected: crlf-test")
				}
				if strings.Contains(val, "session=hijacked") {
					w.Header().Set("Set-Cookie", "session=hijacked")
				}
			} else {
				fmt.Fprintf(w, "Currency test %d: %s", i, val)
			}
			return true
		}
	}
	return false
}

func checkCartVulns(w http.ResponseWriter, r *http.Request) bool {
	r.ParseForm()
	for i := 1; i <= 10; i++ {
		if val := r.FormValue(fmt.Sprintf("cart%d", i)); val != "" {
			if hasSqliPayload(val) {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error: SQLite3.OperationalError: near \"'\": syntax error.")
			} else {
				fmt.Fprintf(w, "Cart test %d: %s", i, val)
			}
			return true
		}
		if val := r.FormValue(fmt.Sprintf("cxss%d", i)); val != "" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body>Results: %s</body></html>", val)
			return true
		}
	}
	return false
}
