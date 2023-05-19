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
	publicKey string
	header    tFileEncryptHeader
}

type tFileEncryptHeader struct {
	AESKey    []byte `json:"k"`
	IV        []byte `json:"i"`
	TimeStamp int64  `json:"t"`
}

func NewFileEncrypt(publicKey string) *tFileEncrypt {
	return &tFileEncrypt{publicKey: publicKey}
}

// Encrypt file using a public key. File is encrypted in stream using AES. AES key and IV are random generated.
// AES key and IV are encrypted with public key and stored in the header of the encrypted file.
func (c *tFileEncrypt) Encrypt(inputFile, outputFile string) error {
	// Open input file
	infile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer infile.Close()

	// Prepare data
	block, iv, OsOutFile, err := c.prepareData(outputFile)
	if err != nil {
		return err
	}
	defer OsOutFile.Close()

	// Encrypt file
	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, iv)
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			OsOutFile.Write(buf[:n])
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

func (c *tFileEncrypt) prepareData(outputFile string) (block cipher.Block, iv []byte, outFile *os.File, err error) {
	// Random 32 byte key for AES encryption
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, nil, nil, err
	}
	// Create AES block cipher
	block, err = aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, nil, err
	}
	// Random IV
	iv = make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, nil, err
	}
	// Read public key
	publicKey, err := c.bytesToPublicKey(c.publicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	// Encrypt AES key with public key
	encryptedAESKey, err := c.encryptWithPublicKey(aesKey, publicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	// Encrypt IV with public key
	encryptedIV, err := c.encryptWithPublicKey(iv, publicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create header
	c.header = tFileEncryptHeader{AESKey: encryptedAESKey, IV: encryptedIV, TimeStamp: time.Now().Unix()}
	headerBytes, err := json.Marshal(c.header)
	if err != nil {
		return nil, nil, nil, err
	}
	headerBytes = []byte(base64.StdEncoding.EncodeToString(headerBytes))

	// Open output file
	outfile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, nil, nil, err
	}

	// Write header
	outfile.Write([]byte("sme"))
	outfile.Write(headerBytes)
	outfile.Write([]byte{0})

	return block, iv, outfile, nil
}

// Read data from io.Writer and encrypt. Data is encrypted in stream using AES.
// AES key and IV are random generated. AES key and IV are encrypted with public key and stored in the header of the encrypted file.
func (c *tFileEncrypt) EncryptReader(outputFile string) (w io.Writer, err error) {
	// Prepare data
	block, iv, OsOutfile, err := c.prepareData(outputFile)
	if err != nil {
		return nil, err
	}

	// read w to buffer
	r, w := io.Pipe()

	// Encrypt file
	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, iv)
	go func() {
		for {
			n, err := r.Read(buf)
			if string(buf[:n]) == "EndOfFile" {
				break
			}
			if n > 0 {
				stream.XORKeyStream(buf, buf[:n])
				OsOutfile.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Printf("Read %d bytes: %v", n, err)
				break
			}
		}
		OsOutfile.Close()
		fmt.Println("EncryptReader: EOF")
	}()

	return w, nil

}

func (c *tFileEncrypt) encryptWithPublicKey(msg []byte, pub *rsa.PublicKey) (encryptedBytes []byte, err error) {
	hash := sha512.New()
	encryptedBytes, err = rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}
	return encryptedBytes, nil
}

func (c *tFileEncrypt) bytesToPublicKey(pubKeyFile string) (publicKey *rsa.PublicKey, err error) {
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
	header, err := c.parseHeader(infile)
	if err != nil {
		return err
	}
	// Read private key
	privateKey, err := c.bytesToPrivateKey(privKeyFile)
	if err != nil {
		return err
	}
	// Decrypt AES key
	decryptedAESKey, err := c.decryptWithPrivateKey(header.AESKey, privateKey)
	if err != nil {
		return err
	}
	// Decrypt IV
	decryptedIV, err := c.decryptWithPrivateKey(header.IV, privateKey)
	if err != nil {
		return err
	}

	// Prepare AES block cipher
	block, err := aes.NewCipher(decryptedAESKey)
	if err != nil {
		log.Panic(err)
	}
	// Open output file
	outfile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
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

func (c *tFileEncrypt) decryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) (decryptedBytes []byte, err error) {
	hash := sha512.New()
	decryptedBytes, err = rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return decryptedBytes, nil
}

func (c *tFileEncrypt) bytesToPrivateKey(privKeyFile string) (privateKey *rsa.PrivateKey, err error) {
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

func (c *tFileEncrypt) parseHeader(infile *os.File) (header tFileEncryptHeader, err error) {
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
