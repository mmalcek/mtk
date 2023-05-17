package mtk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

type tFileEncrypt struct {
	header tFileEncryptHeader
}

type tFileEncryptHeader struct {
	AESKey    []byte `json:"aes_key"`
	IV        []byte `json:"iv"`
	TimeStamp int64  `json:"time_stamp"`
}

func NewFileEncrypt() *tFileEncrypt {
	return &tFileEncrypt{}
}

// Encrypt file using a public key. File is encrypted in stream using AES. AES key and IV are random generated.
// AES key and IV are encrypted with public key and stored in the header of the encrypted file.
func (c *tFileEncrypt) Encrypt(inputFile, outputFile, pubKeyFile string) error {
	// Open input file
	infile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer infile.Close()

	// Random 32 byte key for AES encryption
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return err
	}
	// Create AES block cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	// Random IV
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}
	// Open output file
	outfile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return err
	}
	defer outfile.Close()
	// Read public key
	publicKey, err := bytesToPublicKey(pubKeyFile)
	if err != nil {
		return err
	}
	// Encrypt AES key with public key
	encryptedAESKey, err := encryptWithPublicKey(aesKey, publicKey)
	if err != nil {
		return err
	}
	// Encrypt IV with public key
	encryptedIV, err := encryptWithPublicKey(iv, publicKey)
	if err != nil {
		return err
	}

	// Create header
	c.header = tFileEncryptHeader{AESKey: encryptedAESKey, IV: encryptedIV, TimeStamp: time.Now().Unix()}
	headerBytes, err := json.Marshal(c.header)
	if err != nil {
		return err
	}
	headerBytes = []byte(base64.StdEncoding.EncodeToString(headerBytes))

	// Write header
	outfile.Write([]byte("sme"))
	outfile.Write(headerBytes)
	outfile.Write([]byte{0})

	// Encrypt file
	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, iv)
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			outfile.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Read %d bytes: %v", n, err)
			break
		}
	}
	return nil
}

func encryptWithPublicKey(msg []byte, pub *rsa.PublicKey) (encryptedBytes []byte, err error) {
	hash := sha512.New()
	encryptedBytes, err = rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}
	return encryptedBytes, nil
}

func bytesToPublicKey(pubKeyFile string) (publicKey *rsa.PublicKey, err error) {
	pubKeyBytes, err := os.ReadFile(pubKeyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pubKeyBytes)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return key, nil
}

// Decrypt file using a private key. File is decrypted in stream using AES.
// AES key and IV are read from the header of the encrypted file and decrypted with the private key.
func (c *tFileEncrypt) Decrypt(inputFile, outputFile, privKeyFile string) error {
	// Open input file
	infile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer infile.Close()

	// Parse header
	header, err := parseHeader(infile)
	if err != nil {
		return err
	}
	// Read private key
	privateKey, err := BytesToPrivateKey(privKeyFile)
	if err != nil {
		return err
	}
	// Decrypt AES key
	decryptedAESKey, err := decryptWithPrivateKey(header.AESKey, privateKey)
	if err != nil {
		return err
	}
	// Decrypt IV
	decryptedIV, err := decryptWithPrivateKey(header.IV, privateKey)
	if err != nil {
		return err
	}

	// Prepare AES block cipher
	block, err := aes.NewCipher(decryptedAESKey)
	if err != nil {
		log.Panic(err)
	}
	// Open output file
	outfile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()
	// Decrypt file and write to output file
	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, decryptedIV)
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			outfile.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Read %d bytes: %v", n, err)
			break
		}
	}
	return nil
}

func decryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) (decryptedBytes []byte, err error) {
	hash := sha512.New()
	decryptedBytes, err = rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return decryptedBytes, nil
}

func BytesToPrivateKey(privKeyFile string) (privateKey *rsa.PrivateKey, err error) {
	privKeyBytes, err := os.ReadFile(privKeyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(privKeyBytes)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	privateKey, err = x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func parseHeader(infile *os.File) (header tFileEncryptHeader, err error) {
	// Read header
	marker := make([]byte, 3)
	if _, err := io.ReadFull(infile, marker); err != nil {
		return header, err
	}
	// Check marker
	if string(marker) != "sme" {
		return header, errors.New("invalid file format")
	}
	headerBytes := make([]byte, 0)
	// Read header bytes
	for {
		b := make([]byte, 1)
		if _, err := io.ReadFull(infile, b); err != nil {
			return header, err
		}
		if b[0] == 0x00 { // null byte - end of header section
			break
		}
		headerBytes = append(headerBytes, b[0])
	}
	// Decode header
	headerBase64, err := base64.StdEncoding.DecodeString(string(headerBytes))
	if err != nil {
		return header, err
	}
	if err := json.Unmarshal(headerBase64, &header); err != nil {
		return header, err
	}
	return header, nil
}
