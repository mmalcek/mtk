package mtk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
)

// Encrypt the file using AES (CBC) using random key. The random key is then encrypted using RSA public key and stored at the begining of the file.
func FileEncrypt(publicKeyFile, inputFile, outputFile string) error {
	infile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer infile.Close()

	AESKey := make([]byte, 32)
	if _, err := rand.Read(AESKey); err != nil {
		return err
	}

	block, err := aes.NewCipher(AESKey)
	if err != nil {
		return err
	}

	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	outfile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return err
	}
	defer outfile.Close()

	publicKey, err := bytesToPublicKey(publicKeyFile)
	if err != nil {
		return err
	}

	encryptedAESKey, err := encryptWithPublicKey(AESKey, publicKey)
	if err != nil {
		return err
	}

	outfile.Write(encryptedAESKey)

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
	outfile.Write(iv)
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

// Decrypt the file using AES (CBC) key stored at the begining of the file RSA encrypted. The RSA private key is used to decrypt the AES key.
func FileDecrypt(privateKeyFile, inputFile, outputFile string) error {
	infile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer infile.Close()

	encryptedAESKey := make([]byte, 256)
	if _, err := io.ReadFull(infile, encryptedAESKey); err != nil {
		return err
	}

	privateKey, err := BytesToPrivateKey(privateKeyFile)
	if err != nil {
		return err
	}

	decryptedAESKey, err := decryptWithPrivateKey(encryptedAESKey, privateKey)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(decryptedAESKey)
	if err != nil {
		return err
	}

	fi, err := infile.Stat()
	if err != nil {
		return err
	}

	iv := make([]byte, block.BlockSize())
	msgLen := fi.Size() - int64(len(iv))
	if _, err = infile.ReadAt(iv, msgLen); err != nil {
		return err
	}

	outfile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return err
	}
	defer outfile.Close()

	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, iv)
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			// The last bytes are the IV, don't belong the original message - length of password stored at the begining of the file
			if n > int(msgLen-256) {
				n = int(msgLen - 256)
			}
			msgLen -= int64(n)
			stream.XORKeyStream(buf, buf[:n])
			outfile.Write(buf[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("Read %d bytes: %v", n, err)
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
