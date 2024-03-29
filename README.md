# mtk
Personal toolkit with useful functions

## DPAPI
Data Protection Application Programming Interface (DPAPI) is a simple cryptographic application programming interface available as a built-in component in Windows 2000 and later versions of Microsoft Windows operating systems. In theory, the Data Protection API can enable symmetric encryption of any kind of data; in practice, its primary use in the Windows operating system is to perform symmetric encryption of asymmetric private keys, using a user or system secret as a significant contribution of entropy.
[https://en.wikipedia.org/wiki/Data_Protection_API](https://en.wikipedia.org/wiki/Data_Protection_API)

- Initialize DPAPI
```go
dpapi := mtk.NewDPAPI()
```

- Encrypt data (data, entropy, localMachine)
    - data: array of bytes
    - entropy: is used as aditional key/appIdentfier (optional)
    - localMachine: is used to encrypt data for all users (false = current)
    - Returns base64 encoded encrypted data
```go
encrypted, err := dpapi.Encrypt([]byte("Hello World"), "myKey", false)
```

- Decrypt data (data, entropy)
    - entropy: must be the same as used for encryption
    - Returns decrypted array of bytes
```go
decrypted, err :=  dpapi.Decrypt(encrypted, "myKey")
```

## AES
- Encrypt AES
    - data: array of bytes
    - key: Any password string that is automatically salted and hashed
    - Returns base64 encoded encrypted data
```go
encrypted, err := mtk.AESencrypt([]byte(text), "myKey")
```

- Decrypt AES    
    - key: Any password string that is automatically salted and hashed
    - Returns decrypted array of bytes
```go
decrypted, err :=  mtk.AESdecrypt(encrypted, "myKey")
```

## Encrypt file using Private/public keys in stream
```go
	fe, err := mtk.FileEncrypt("publicKey", "outputFile") // returns io.Writer
	if err != nil {
		panic(err)
	}
	if err := fe.Decrypt("input.sme", "output.txt", "private.pem", []byte("Password")); err != nil {
		panic(err)
	}
```

## TarGz multiple folders including subfolder
```go
    tgz := mtk.NewTarGz()
	tgz.Archive([]string{"C:/folder1/data1", "C:/folder2/data3"}, "test.tar.gz")
```

## TarGz and encrypt with public key
```go
	fe := mtk.NewFileEncrypt("public.pem")
	tgz := mtk.NewTarGz()

	var done = make(chan bool) // Channel to wait for encryption to finish
	encryptReader, err := fe.EncryptReader("test.tar.gz.sme", done)
	if err != nil {
		panic(err)
	}
	if err := tgz.ArchiveWriter([]string{"C:/folder1/data1", "C:/folder2/data3"}, encryptReader); err != nil {
		panic(err)
	}
	<-done // Wait for encryption to finish
```

## Generate RSA key pair
```go
	keys, err := mtk.NewKeyPair(2048)
	if err != nil {
		panic(err)
	}
	// Private key to file
	if err := os.WriteFile("private.pem", keys.PrivateKey, 0644); err != nil {
		panic(err)
	}
	// Public key to file
	if err := os.WriteFile("public.pem", keys.PublicKey, 0644); err != nil {
		panic(err)
	}
```


## MachineID
machineID returns the key MachineGuid in registry `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`. If there is an error running the commad an empty string is returned.

```go
machineID := mtk.MachineID()
```



