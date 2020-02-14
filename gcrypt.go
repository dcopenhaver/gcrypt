package gcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"os"
)

// FUNCTIONS ---------------------------------

func CreateHash(value string, algo string) string {

	var sum_bytes []byte

	switch algo {

	case "sha1":
		hasher := sha1.New()
		io.WriteString(hasher, value)
		sum_bytes = hasher.Sum(nil)

	case "sha256":
		hasher := sha256.New()
		io.WriteString(hasher, value)
		sum_bytes = hasher.Sum(nil)

	case "sha512":
		hasher := sha512.New()
		io.WriteString(hasher, value)
		sum_bytes = hasher.Sum(nil)

	case "md5":
		hasher := md5.New()
		io.WriteString(hasher, value)
		sum_bytes = hasher.Sum(nil)

	default:
		log.Fatalln("Valid algo was not passed in to function: CreateHash. \nalgo options: sha1, sha256, sha512, md5")
	}

	return hex.EncodeToString(sum_bytes)
}

func CreateFileHash(algo string, pathToFile string) string {

	f, err := os.Open(pathToFile)
	if err != nil {
		log.Fatalf("Error opening file %s\n%s", pathToFile, err)
	}

	defer f.Close()

	var sum_bytes []byte

	switch algo {

	case "sha1":
		hasher := sha1.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatalf("Error during io.Copy.\n%s", err)
		}

		sum_bytes = hasher.Sum(nil)

	case "sha256":
		hasher := sha256.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatalf("Error during io.Copy.\n%s", err)
		}

		sum_bytes = hasher.Sum(nil)

	case "sha512":
		hasher := sha512.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatalf("Error during io.Copy.\n%s", err)
		}

		sum_bytes = hasher.Sum(nil)

	case "md5":
		hasher := md5.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatalf("Error during io.Copy.\n%s", err)
		}

		sum_bytes = hasher.Sum(nil)

	default:
		log.Fatalln("Valid algo was not passed in to function: CreateFileHash.\nalgo options: sha1, sha256, sha512, md5.")
	}

	return hex.EncodeToString(sum_bytes)
}

// AES128/256, GCM
func Encrypt(plaintext_bytes []byte, passphrase string, algo string) ([]byte, error) {

	// AES 128 or 256 determined by key size, 16 bytes for AES128 and 32 bytes for AES256
	// key derived by hashing passphrase to appropriate length

	key, _ := hex.DecodeString(CreateHash(passphrase, "sha256")) // returns []byte, error

	switch algo {

	case "aes128":
		// grab first 16 bytes for AES128 key
		key = key[:16]

	case "aes256":
		// k, all good, key is already 32 bytes

	default:
		return nil, errors.New("Encrypt: Invalid algo, must be aes128 or aes256.")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext_bytes, nil), nil
}

func Decrypt(ciphertext_bytes []byte, passphrase string, algo string) ([]byte, error) {

	key, _ := hex.DecodeString(CreateHash(passphrase, "sha256")) // returns []byte, error

	switch algo {

	case "aes128":
		// grab first 16 bytes for AES128 key
		key = key[:16]

	case "aes256":
		// k, all good, key is already 32 bytes

	default:
		return nil, errors.New("Encrypt: Invalid algo, must be aes128 or aes256.")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext_bytes) < gcm.NonceSize() {
		return nil, errors.New("Malformed ciphertext")
	}

	return gcm.Open(nil, ciphertext_bytes[:gcm.NonceSize()], ciphertext_bytes[gcm.NonceSize():], nil)
}
