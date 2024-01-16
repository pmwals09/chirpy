package database

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"sync"
)

type DB struct {
	path string
	mu   *sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

type ErrChirpNotFound struct{}

func (e ErrChirpNotFound) Error() string {
	return "Chirp not found in database"
}

type ErrUserExists struct{}

func (e ErrUserExists) Error() string {
	return "User already exists in database"
}

type ErrUserDoesNotExist struct{}

func (e ErrUserDoesNotExist) Error() string {
	return "User does not exist in database"
}

func NewDB(path string) (*DB, error) {
	db := DB{path: path, mu: &sync.RWMutex{}}
	err := db.ensureDB()
	if err != nil {
		return &db, err
	}
	return &db, nil
}

func (db *DB) CreateChirp(body string) (Chirp, error) {
	c := Chirp{Body: body}
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

func (db *DB) GetChirpById(id string) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	chirpID, err := strconv.Atoi(id)
	if err != nil {
		return Chirp{}, err
	}
	if chirp, ok := dbStructure.Chirps[chirpID]; ok {
		return chirp, nil
	} else {
		return Chirp{}, ErrChirpNotFound{}
	}
}

func (db *DB) CreateUser(email string, pwHash string) (User, error) {
	user := User{Email: email, PasswordHash: pwHash}
	dbStructure, err := db.loadDB()
	if err != nil {
		return user, err
	}
	for _, u := range dbStructure.Users {
		if u.Email == user.Email {
			return user, ErrUserExists{}
		}
		if u.Id > user.Id {
			user.Id = u.Id
		}
	}
	user.Id += 1
	dbStructure.Users[user.Id] = user
	err = db.writeDB(dbStructure)
	if err != nil {
		return user, err
	}
	return user, nil
}

func (db *DB) GetUserByEmail(email string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	for _, u := range dbStructure.Users {
		if u.Email == email {
			return u, nil
		}
	}
	return User{}, errors.New("User not found")
}

func (db *DB) UpdateUser(id int, email string, pwHash string) (User, error) {
	user := User{Email: email, PasswordHash: pwHash, Id: id}
	dbStructure, err := db.loadDB()
	if err != nil {
		return user, err
	}

	if _, ok := dbStructure.Users[user.Id]; ok {
		dbStructure.Users[id] = user
		err := db.writeDB(dbStructure)
		if err != nil {
			return user, err
		}
		return user, nil
	} else {
		return user, ErrUserDoesNotExist{}
	}

}

func (db *DB) ensureDB() error {
	if _, err := os.Stat(db.path); errors.Is(err, os.ErrNotExist) {
		err := os.WriteFile(db.path, []byte("{\"chirps\": {}, \"users\": {}}"), 0644)
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
