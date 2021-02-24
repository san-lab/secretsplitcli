package goethkey

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/google/uuid"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

var Verbose bool

type Keyfile struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Address string `json:"address"`
	Crypto  struct {
		Ciphertext   string `json:"ciphertext"`
		Cipherparams struct {
			Iv string `json:"iv"`
		} `json:"cipherparams"`
		Cipher          string          `json:"cipher"`
		Kdf             string          `json:"kdf"`
		KdfparamsPack   json.RawMessage `json:"kdfparams,omitempty"`
		KdfScryptParams KdfScryptparams `json:"-"`
		Mac             string          `json:"mac"`
	} `json:"crypto"`
	Plaintext []byte `json:"-"`
}

type KdfScryptparams struct {
	Dklen int    `json:"dklen"`
	Salt  string `json:"salt"`
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
}

func ReadKeyfile(password []byte, filename string) (*Keyfile, error) {
	filebytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	kf := Keyfile{}
	err = json.Unmarshal(filebytes, &kf)
	switch kf.Crypto.Kdf {
	case "scrypt":
		ksp := new(KdfScryptparams)
		err = json.Unmarshal(kf.Crypto.KdfparamsPack, ksp)
		kf.Crypto.KdfScryptParams = *ksp

	}
	return &kf, err

}

func KeyFromPassScrypt(password []byte, params KdfScryptparams) ([]byte, error) {
	salt, err := hex.DecodeString(params.Salt)
	if err != nil {
		return nil, err
	}
	return scrypt.Key(password, salt, params.N, params.R, params.P, params.Dklen)
}

//Just a convenience wrapper copied from geth
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

func EncryptAES128(kf *Keyfile, plaintext []byte, password []byte) error {
	key, err := KeyFromPassScrypt(password, kf.Crypto.KdfScryptParams)
	if err != nil {
		return err
	}
	//Letsencrypt
	iv := make([]byte, 16)
	rand.Read(iv)

	block, err := aes.NewCipher(key[0:16])
	if err != nil {
		return err
	}
	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	kf.Crypto.Cipherparams.Iv = hex.EncodeToString(iv)
	kf.Crypto.Ciphertext = hex.EncodeToString(ciphertext)
	kf.Crypto.Cipher = "aes-128-ctr"

	mac := Keccak256(append(key[16:], ciphertext...))
	kf.Crypto.Mac = hex.EncodeToString(mac)
	kf.Version = 3
	//_, pubkeyec := btcec.PrivKeyFromBytes(btcec.S256(), ethkey)
	//pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)

	xuuid, err := uuid.NewUUID()
	kf.ID = xuuid.String()
	parambytes, err := json.Marshal(&kf.Crypto.KdfScryptParams)
	return kf.Crypto.KdfparamsPack.UnmarshalJSON(parambytes)

}

func SetPassword() ([]byte, error) {
	var pass, p2 []byte
	var err error
	for {
		pass, err = ReadPassword("Password for the keyfile:")
		if err != nil {
			return nil, err
		}
		p2, err = ReadPassword("Repeat password:")
		if err != nil {
			return nil, err
		}
		if len(pass) < 6 {
			fmt.Println("Password too short, try again\n")
			continue
		}
		if bytes.Equal(pass, p2) {
			return pass, nil
		}
		fmt.Println("Passwords do not match, try again\n")
	}
}

//Reading a password on a CLI without echoing it
func ReadPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	defer fmt.Print("\n")
	fd := int(os.Stdin.Fd())
	//Sadly terminal will not work under IDE, hence the 'else'
	if terminal.IsTerminal(fd) {
		return terminal.ReadPassword(fd)
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		pass := scanner.Bytes()
		return pass, nil
	}

}

func DecryptAES128CTR(kf *Keyfile, key []byte) (privkey []byte, err error) {
	block, err := aes.NewCipher(key[0:16])
	if err != nil {
		return
	}
	iv, err := hex.DecodeString(kf.Crypto.Cipherparams.Iv)
	if err != nil {
		return
	}
	stream := cipher.NewCTR(block, iv)
	citx, err := hex.DecodeString(kf.Crypto.Ciphertext)
	if err != nil {
		return
	}
	privkey = make([]byte, len(citx))
	stream.XORKeyStream(privkey, citx)
	return

}
