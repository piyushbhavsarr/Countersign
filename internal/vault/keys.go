package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Keyring holds the keys that seal what the vault stores (AES-256-GCM). It lives apart from
// the replicas, so that destroying a key (crypto-shredding) makes every copy of what it
// sealed unreadable at once, on every replica and in every backup of them, without
// touching the replicas. New entries are sealed with the active key; Rotate starts a new
// one (for example one per month or per customer), so each can be shredded on its own.
type Keyring struct {
	path string
	mu   sync.Mutex
	f    keyFile
}

type keyFile struct {
	Active   string             `json:"active"`
	Keys     map[string][]byte  `json:"keys"`
	Shredded map[string]float64 `json:"shredded,omitempty"` // key id -> when it was destroyed
}

// OpenKeyring reads the keyring at path, creating it with one key if it does not exist.
func OpenKeyring(path string) (*Keyring, error) {
	k := &Keyring{path: path}
	b, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		k.f = keyFile{Keys: map[string][]byte{}, Shredded: map[string]float64{}}
		if _, err := k.rotateLocked(); err != nil {
			return nil, err
		}
		return k, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &k.f); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if k.f.Keys == nil {
		k.f.Keys = map[string][]byte{}
	}
	if k.f.Shredded == nil {
		k.f.Shredded = map[string]float64{}
	}
	if len(k.f.Keys[k.f.Active]) != 32 {
		return nil, fmt.Errorf("%s: the active key is missing", path)
	}
	return k, nil
}

func (k *Keyring) save() error {
	b, err := json.MarshalIndent(k.f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	tmp := k.path + ".tmp-" + rnd()
	if err := writeFileSync(tmp, b); err != nil {
		return err
	}
	if err := os.Rename(tmp, k.path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(k.path))
}

func (k *Keyring) rotateLocked() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	id := fmt.Sprintf("k%d-%s", time.Now().Unix(), rnd()[:4])
	k.f.Keys[id], k.f.Active = key, id
	return id, k.save()
}

// Rotate makes a new active key. Entries sealed earlier keep their key.
func (k *Keyring) Rotate() (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.rotateLocked()
}

// Shred destroys a key: everything it sealed becomes unreadable, everywhere. If it is the
// active key, a new one is made first.
func (k *Keyring) Shred(id string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.f.Keys[id]; !ok {
		return fmt.Errorf("no key %s", id)
	}
	if id == k.f.Active {
		if _, err := k.rotateLocked(); err != nil {
			return err
		}
	}
	delete(k.f.Keys, id)
	k.f.Shredded[id] = float64(time.Now().UnixNano()) / 1e9
	return k.save()
}

// KeyInfo describes the keys without revealing them.
type KeyInfo struct {
	Active   string             `json:"active"`
	Keys     []string           `json:"keys"`
	Shredded map[string]float64 `json:"shredded"`
}

func (k *Keyring) Info() KeyInfo {
	k.mu.Lock()
	defer k.mu.Unlock()
	ids := []string{}
	for id := range k.f.Keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	sh := map[string]float64{}
	for id, t := range k.f.Shredded {
		sh[id] = t
	}
	return KeyInfo{Active: k.f.Active, Keys: ids, Shredded: sh}
}

func (k *Keyring) aead(id string) (cipher.AEAD, error) {
	k.mu.Lock()
	key, ok := k.f.Keys[id]
	_, shredded := k.f.Shredded[id]
	k.mu.Unlock()
	if !ok {
		if shredded {
			return nil, ErrShredded
		}
		return nil, fmt.Errorf("vault: key %s is not in the keyring", id)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// ErrShredded: the key that sealed this content was destroyed on purpose.
var ErrShredded = errors.New("vault: sealed with a key that was shredded")

func (k *Keyring) seal(aad, plain []byte) (id string, sealed []byte, err error) {
	k.mu.Lock()
	id = k.f.Active
	k.mu.Unlock()
	g, err := k.aead(id)
	if err != nil {
		return "", nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, err
	}
	return id, g.Seal(nonce, nonce, plain, aad), nil
}

func (k *Keyring) open(id string, aad, sealed []byte) ([]byte, error) {
	g, err := k.aead(id)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize() {
		return nil, errors.New("vault: sealed content too short")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
}
