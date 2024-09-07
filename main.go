package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

// Estructuras
type UserInfo struct {
	PeerID   string `json:"peerId"`
	Username string `json:"username"`
	Photo    string `json:"photo"`
}

type Comment struct {
	Username string `json:"username"`
	Comment  string `json:"comment"`
}

type Content struct {
	Title      string    `json:"title"`
	Message    string    `json:"message"`
	Subtitle   string    `json:"subtitle"`
	Likes      int       `json:"likes"`
	Comments   []Comment `json:"comments"`
	Subscribed bool      `json:"subscribed"`
	VideoURL   string    `json:"videoUrl"`
}

type Message struct {
	ID        string    `json:"id"`
	From      UserInfo  `json:"from"`
	To        string    `json:"to"`
	Timestamp string    `json:"timestamp"`
	Content   Content   `json:"content"`
}

type Tablon struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Messages []Message `json:"messages"`
	Geo      string    `json:"geo"`
	Likes    int       `json:"likes"`
}

var (
	tablones      []Tablon
	tablonesMutex sync.Mutex
)

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func createTablonHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "Missing 'name' query parameter", http.StatusBadRequest)
		return
	}

	tablon := Tablon{
		ID:       generateID(),
		Name:     name,
		Messages: []Message{},
		Geo:      "",
		Likes:    0,
	}

	tablonesMutex.Lock()
	tablones = append(tablones, tablon)
	tablonesMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "tablon created", "id": tablon.ID})
}

func readTablonHandler(w http.ResponseWriter, r *http.Request) {
	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tablones)
}

func addLikeToTablonHandler(w http.ResponseWriter, r *http.Request) {
	tablonID := r.URL.Query().Get("tablon_id")
	if tablonID == "" {
		http.Error(w, "Missing 'tablon_id' query parameter", http.StatusBadRequest)
		return
	}

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			tablones[i].Likes++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]int{"likes": tablones[i].Likes})
			return
		}
	}

	http.Error(w, "Tablon not found", http.StatusNotFound)
}

func addMessageToTablonHandler(w http.ResponseWriter, r *http.Request) {
	tablonID := r.URL.Query().Get("tablon_id")
	if tablonID == "" {
		http.Error(w, "Missing 'tablon_id' query parameter", http.StatusBadRequest)
		return
	}

	messageContent := r.URL.Query().Get("message")
	if messageContent == "" {
		http.Error(w, "Missing 'message' query parameter", http.StatusBadRequest)
		return
	}

	videoURL := r.URL.Query().Get("videoUrl")

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			msg := Message{
				ID:        generateID(),
				From:      UserInfo{PeerID: "your_peer_id", Username: "your_username", Photo: "your_photo_url"},
				To:        "DESTINATION_PEER_ID",
				Timestamp: time.Now().Format(time.RFC3339),
				Content: Content{
					Title:      "Nuevo Mensaje",
					Message:    messageContent,
					Subtitle:   "Sistema",
					Likes:      0,
					Comments:   []Comment{},
					Subscribed: false,
					VideoURL:   videoURL,
				},
			}

			tablones[i].Messages = append(tablones[i].Messages, msg)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "message added", "id": msg.ID})
			return
		}
	}

	http.Error(w, "Tablon not found", http.StatusNotFound)
}
// Nueva función para manejar likes individuales de mensajes
func addLikeToMessageHandler(w http.ResponseWriter, r *http.Request) {
	tablonID := r.URL.Query().Get("tablon_id")
	messageID := r.URL.Query().Get("message_id")
	if tablonID == "" || messageID == "" {
		http.Error(w, "Missing 'tablon_id' or 'message_id' query parameter", http.StatusBadRequest)
		return
	}

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			for j, msg := range tablon.Messages {
				if msg.ID == messageID {
					tablones[i].Messages[j].Content.Likes++
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]int{"likes": tablones[i].Messages[j].Content.Likes})
					return
				}
			}
			http.Error(w, "Message not found", http.StatusNotFound)
			return
		}
	}

	http.Error(w, "Tablon not found", http.StatusNotFound)
}

func deleteTablonHandler(w http.ResponseWriter, r *http.Request) {
	tablonID := r.URL.Query().Get("tablon_id")
	if tablonID == "" {
		http.Error(w, "Missing 'tablon_id' query parameter", http.StatusBadRequest)
		return
	}

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			tablones = append(tablones[:i], tablones[i+1:]...)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "tablon deleted"})
			return
		}
	}

	http.Error(w, "Tablon not found", http.StatusNotFound)
}

func deleteMessageFromTablonHandler(w http.ResponseWriter, r *http.Request) {
	tablonID := r.URL.Query().Get("tablon_id")
	messageID := r.URL.Query().Get("message_id")
	if tablonID == "" || messageID == "" {
		http.Error(w, "Missing 'tablon_id' or 'message_id' query parameter", http.StatusBadRequest)
		return
	}

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			for j, msg := range tablon.Messages {
				if msg.ID == messageID {
					tablones[i].Messages = append(tablones[i].Messages[:j], tablones[i].Messages[j+1:]...)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]string{"status": "message deleted"})
					return
				}
			}
			http.Error(w, "Message not found", http.StatusNotFound)
			return
		}
	}

	http.Error(w, "Tablon not found", http.StatusNotFound)
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/api/createTablon", createTablonHandler).Methods("POST")
	r.HandleFunc("/api/readTablon", readTablonHandler).Methods("GET")
	r.HandleFunc("/api/addLikeToTablon", addLikeToTablonHandler).Methods("POST")
	r.HandleFunc("/api/addMessage", addMessageToTablonHandler).Methods("POST")
	r.HandleFunc("/api/deleteTablon", deleteTablonHandler).Methods("DELETE")
	r.HandleFunc("/api/deleteMessageFromTablon", deleteMessageFromTablonHandler).Methods("DELETE")
	r.HandleFunc("/api/addLikeToMessage", addLikeToMessageHandler).Methods("POST")
	// Nueva ruta para servir archivos estáticos
	fs := http.FileServer(http.Dir("./web"))
	r.PathPrefix("/web/").Handler(http.StripPrefix("/web/", fs))

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "DELETE", "OPTIONS"},
	})

	handler := c.Handler(r)

	log.Println("Server is running on http://localhost:8080/web/")
	log.Println("Server is running on http://localhost:8080/api/")
	log.Fatal(http.ListenAndServe(":8080", handler))
}