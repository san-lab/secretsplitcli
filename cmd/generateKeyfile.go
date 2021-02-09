/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/spf13/cobra"
	"time"
	"github.com/san-lab/secretsplitcli/goethkey"
	"fmt"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"crypto/aes"
	"crypto/cipher"
	"github.com/btcsuite/btcd/btcec"
	"github.com/google/uuid"
	"encoding/json"
	"io/ioutil"
)

// generateKeyfileCmd represents the generateKeyfile command
var generateKeyfileCmd = &cobra.Command{
	Use:   "generateKeyfile filename",
	Short: "Generate a new keyfile",
	Long: `Generates a new keyfile. Interactively asks for password (do not forget your choice!).`,
	Run: generateKeyfile,
}

var genFilename string
var kdf string

func generateKeyfile(cmd *cobra.Command, args []string) {
	if len(args) == 1 {
		genFilename = args[0]
	} else {
		genFilename = time.Now().Format(time.RFC3339) + ".json"
	}

	kf := goethkey.Keyfile{}

	kf.Crypto.Kdf = kdf
	var pass,p2 []byte
	var err error
	for true {
		pass, err = readPassword("Password for the keyfile:")
		if err != nil {fmt.Println(err); return}
		p2, err = readPassword("Repeat password:")
		if err != nil {fmt.Println(err); return}
		if len(pass) < 6 {fmt.Println("Password too short, try again\n"); continue}
		if bytes.Equal(pass,p2) {break}
		fmt.Println("Passwords do not match, try again\n")
	}


	//for len(pass) <

	//Generate the Koblitz private key
	ethkey := make([]byte, 32)
	rand.Read(ethkey)


	//Derive the key from password
	var key []byte
	salt := make([]byte,16)
	rand.Read(salt)
	/*
	kf.Crypto.KdfparamsPack.Dklen=32
	kf.Crypto.KdfparamsPack.N=131072
	kf.Crypto.KdfparamsPack.P=1
	kf.Crypto.KdfparamsPack.R=8
	kf.Crypto.KdfparamsPack.Salt=hex.EncodeToString(salt)
	*/
	switch kdf {
	case "scrypt":
		kf.Crypto.KdfScryptParams.Dklen=32
		kf.Crypto.KdfScryptParams.N=131072
		kf.Crypto.KdfScryptParams.P=1
		kf.Crypto.KdfScryptParams.R=8
		kf.Crypto.KdfScryptParams.Salt=hex.EncodeToString(salt)
	default:
		fmt.Println("Unsupported KDF scheme")
		return
	}


	key, err = goethkey.KeyFromPassScrypt(pass, kf.Crypto.KdfScryptParams)
	if err != nil { fmt.Println(err) }

	//Letsencrypt
	iv := make([]byte, 16)
	ciphertext := make([]byte, 32)
	rand.Read(iv)

	block, err := aes.NewCipher(key[0:16])
	if err != nil { return}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, ethkey)

	kf.Crypto.Cipherparams.Iv=hex.EncodeToString(iv)
	kf.Crypto.Ciphertext=hex.EncodeToString(ciphertext)
	kf.Crypto.Cipher="aes-128-ctr"

	mac:=goethkey.Keccak256(append(key[16:], ciphertext...))
	kf.Crypto.Mac=hex.EncodeToString(mac)
	kf.Version=3
	//_, pubkeyec := btcec.PrivKeyFromBytes(btcec.S256(), ethkey)
	//pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)

	x, y := btcec.S256().ScalarBaseMult(ethkey)
	pubkeyeth := append(x.Bytes(), y.Bytes()...)
	fmt.Printf("Public key: %s\n", hex.EncodeToString(pubkeyeth))
	kecc := goethkey.Keccak256(pubkeyeth)
	addr := kecc[12:]

	kf.Address=hex.EncodeToString(addr)

	xuuid, err := uuid.NewUUID()
	kf.ID=xuuid.String()
	parambytes , err := json.Marshal( &kf.Crypto.KdfScryptParams)
	kf.Crypto.KdfparamsPack.UnmarshalJSON(parambytes)

	bytes, err := json.Marshal(&kf)
	if err != nil {fmt.Println(err); return}
	ioutil.WriteFile( genFilename, bytes, 0644)
}

func init() {
	rootCmd.AddCommand(generateKeyfileCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// generateKeyfileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// generateKeyfileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	generateKeyfileCmd.Flags().StringVarP(&kdf, "kdf", "", "scrypt", "--kdf preferredKDF")
}
