package mtk

// https://gist.github.com/enyachoke/5c60f5eebed693d9b4bacddcad693b47

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func AESencrypt(data []byte, passphrase string) (string, error) {
	key, salt := deriveKey(passphrase, nil)
	iv := make([]byte, 12)
	rand.Read(iv)
	b, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return "", err
	}
	outputData := aesgcm.Seal(nil, iv, data, nil)
	return base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(salt) + "." + hex.EncodeToString(iv) + "." + hex.EncodeToString(outputData))), nil
}

func AESdecrypt(encodedCipher, passphrase string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encodedCipher)
	if err != nil {
		return nil, err
	}
	arr := strings.Split(string(ciphertext), ".")
	salt, err := hex.DecodeString(arr[0])
	if err != nil {
		return nil, err
	}
	iv, err := hex.DecodeString(arr[1])
	if err != nil {
		return nil, err
	}
	data, err := hex.DecodeString(arr[2])
	if err != nil {
		return nil, err
	}
	key, _ := deriveKey(passphrase, salt)
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	data, err = aesgcm.Open(nil, iv, data, nil)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func deriveKey(passphrase string, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 8)
		rand.Read(salt)
	}
	return pbkdf2.Key([]byte(passphrase), salt, 1000, 32, sha256.New), salt
}
