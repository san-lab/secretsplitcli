package goethkey

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"

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
	Ciphertext []byte `json:"-"`
}

type KdfScryptparams struct {
	Dklen int    `json:"dklen"`
	Salt  string `json:"salt"`
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
}

func ReadKeyfile(filename string) (*Keyfile, error) {
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
