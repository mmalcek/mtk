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

## MachineID
machineID returns the key MachineGuid in registry `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`. If there is an error running the commad an empty string is returned.

```go
machineID := mtk.MachineID()
```

