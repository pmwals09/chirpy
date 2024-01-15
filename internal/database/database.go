package database

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
)

type DB struct {
  path string
  mu *sync.RWMutex
}

type DBStructure struct {
  Chirps map[int]Chirp `json:"chirps"`
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
  db := DB{path: path, mu: &sync.RWMutex{}}
  err := db.ensureDB()
  if err != nil {
    return &db, err
  }
  return &db, nil
}

func (db *DB) CreateChirp(body string) (Chirp, error) {
  c := Chirp {Body: body}
  dbStructure, err := db.loadDB()
  if err != nil {
    return c, err
  }
  for _, chirp := range dbStructure.Chirps {
    if chirp.Id > c.Id {
      c.Id = chirp.Id
    }
  }
  c.Id += 1
  dbStructure.Chirps[c.Id] = c
  err = db.writeDB(dbStructure)
  if err != nil {
    return c, err
  }
  return c, nil
}

func (db *DB) GetChirps() ([]Chirp, error) {
  out := make([]Chirp, 0)
  dbStructure, err := db.loadDB()
  if err != nil {
    return out, err
  }
  for _, chirp := range dbStructure.Chirps {
    out = append(out, chirp)
  }
  sort.Slice(out, func(i, j int) bool {
    return out[i].Id < out[j].Id
  })
  return out, nil
}

func (db *DB) ensureDB() error {
  if _, err := os.Stat(db.path); errors.Is(err, os.ErrNotExist) {
    // create the file
    err := os.WriteFile(db.path, []byte("{\"chirps\": {}}"), 0644)
    if err != nil {
      return err
    }
    return nil
  } else if err != nil {
    return err
  }
  return nil
}

func (db *DB) loadDB() (DBStructure, error) {
  dbStructure := DBStructure{Chirps: make(map[int]Chirp)}
  db.mu.RLock()
  ba, err := os.ReadFile(db.path)
  db.mu.RUnlock()
  if err != nil {
    return dbStructure, err
  }
  err = json.Unmarshal(ba, &dbStructure)
  if err != nil {
    return dbStructure, err
  }
  return dbStructure, nil
}

func (db *DB) writeDB(dbStructure DBStructure) error {
  ba, err := json.Marshal(dbStructure)
  if err != nil {
    return err
  }
  db.mu.Lock()
  err = os.WriteFile(db.path, ba, 0644)
  db.mu.Unlock()
  if err != nil {
    return err
  }
  return nil
}
