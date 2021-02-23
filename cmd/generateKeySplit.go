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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/btcsuite/btcd/btcec"
	"github.com/google/uuid"
	"github.com/san-lab/secretsplitcli/goethkey"
	"github.com/spf13/cobra"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
)

type sharePrishare share.PriShare

// generateKeyfileCmd represents the generateKeyfile command
var generateKeySplitCmd = &cobra.Command{
	Use:   "generateKeySplit totalShares MinShares baseFilename privatekey",
	Short: "Generates shamir secret shares of a private key",
	Long:  `Generates shamir secret shares of a private key. Interactively asks for passwords (do not forget your choice!).`,
	Run:   generateKeySplit,
}

var numShares, minShares int
var genFilenameBase string
var kdfNew string

var ethkeyStr string
var ethkey []byte

//var DefaultPrimeStr = "115792089237316195423570985008687907853269984665640564039457584007913129639747"
//var defaultPrime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

//This is a hack for overloading the ID field of the keyfile
//If the first 16 runes/8 bytes are equal to SplitHeader
//the next 2 runes encode the quorum count (quorum <256)
const SplitHeader = "SplitKey"

func generateKeySplit(cmd *cobra.Command, args []string) {
	if numShares > 255 || minShares > numShares {
		fmt.Println("Invalid split parameters:", numShares, minShares)
		return
	}
	var poly *share.PriPoly
	if len(ethkeyStr) == 0 {

		fmt.Printf("Generating %v of %v split of a new random key\n", minShares, numShares)

		suite := suites.MustFind("bn256.G2")
		secretScalar := pairing.NewSuiteBn256().G2().Scalar().Pick(suite.RandomStream())
		poly = share.NewPriPoly(pairing.NewSuiteBn256().G2(), minShares, secretScalar, pairing.NewSuiteBn256().RandomStream())
		fmt.Println("Secret key", secretScalar)
	} else {
		fmt.Printf("Generating %v of %v split of the key provided\n", minShares, numShares)
		ethkey, err := hex.DecodeString(ethkeyStr)
		if err != nil {
			fmt.Println(err)
			return
		}
		secretScalar := pairing.NewSuiteBn256().G2().Scalar().SetBytes(ethkey)
		poly = share.NewPriPoly(pairing.NewSuiteBn256().G2(), minShares, secretScalar, pairing.NewSuiteBn256().RandomStream())
		fmt.Println("Secret scalar", secretScalar)
	}

	sharesN := poly.Shares(numShares)

	var arrayShareBytes [][]byte
	for _, s := range sharesN {
		var shareTemp = sharePrishare{s.I, s.V}
		b, _ := shareTemp.MarshalJSON()
		arrayShareBytes = append(arrayShareBytes, b)
	}
	xuuid, err := uuid.NewUUID()
	if err != nil {
		fmt.Println(err)
		return
	}
	for i := 0; i < len(arrayShareBytes); i++ {
		keyFileName := fmt.Sprintf("%s%vof%v.json", genFilenameBase, i+1, numShares)
		fmt.Printf("Generating keyfile No %v (%s)\n", i+1, keyFileName)
		shareBytes := arrayShareBytes[i]
		kf := goethkey.Keyfile{}

		kf.Crypto.Kdf = kdfNew
		var pass, p2 []byte
		var err error
		for true {
			pass, err = readPassword("Password for the keyfile:")
			fmt.Print("\n")
			if err != nil {
				fmt.Println(err)
				return
			}
			p2, err = readPassword("Repeat password:")
			fmt.Print("\n")
			if err != nil {
				fmt.Println(err)
				return
			}
			if len(pass) < 6 {
				fmt.Println("Password too short, try again\n")
				continue
			}
			if bytes.Equal(pass, p2) {
				break
			}
			fmt.Println("Passwords do not match, try again\n")
		}

		//Derive the key from password
		var key []byte
		salt := make([]byte, 16)
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
			kf.Crypto.KdfScryptParams.Dklen = 32
			kf.Crypto.KdfScryptParams.N = 131072
			kf.Crypto.KdfScryptParams.P = 1
			kf.Crypto.KdfScryptParams.R = 8
			kf.Crypto.KdfScryptParams.Salt = hex.EncodeToString(salt)
		default:
			fmt.Println("Unsupported KDF scheme")
			return
		}

		key, err = goethkey.KeyFromPassScrypt(pass, kf.Crypto.KdfScryptParams)
		if err != nil {
			fmt.Println(err)
		}

		//Letsencrypt
		iv := make([]byte, 16)
		ciphertext := make([]byte, len(shareBytes))
		rand.Read(iv)

		block, err := aes.NewCipher(key[0:16])
		if err != nil {
			return
		}
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(ciphertext, shareBytes)

		kf.Crypto.Cipherparams.Iv = hex.EncodeToString(iv)
		kf.Crypto.Ciphertext = hex.EncodeToString(ciphertext)
		kf.Crypto.Cipher = "aes-128-ctr"

		mac := goethkey.Keccak256(append(key[16:], ciphertext...))
		kf.Crypto.Mac = hex.EncodeToString(mac)
		kf.Version = 3
		//_, pubkeyec := btcec.PrivKeyFromBytes(btcec.S256(), ethkey)
		//pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)

		x, y := btcec.S256().ScalarBaseMult(shareBytes)
		pubkeyeth := append(x.Bytes(), y.Bytes()...)
		//fmt.Printf("Public key: %s\n", hex.EncodeToString(pubkeyeth))
		kecc := goethkey.Keccak256(pubkeyeth)
		addr := kecc[12:]

		kf.Address = hex.EncodeToString(addr)

		kf.ID = SplitHeader + hex.EncodeToString([]byte{byte(minShares)}) + hex.EncodeToString([]byte{byte(i)}) + "-" + xuuid.String()
		parambytes, err := json.Marshal(&kf.Crypto.KdfScryptParams)
		kf.Crypto.KdfparamsPack.UnmarshalJSON(parambytes)

		bytes, err := json.Marshal(&kf)
		if err != nil {
			fmt.Println(err)
			return
		}
		ioutil.WriteFile(keyFileName, bytes, 0644)
		fmt.Printf("File %s generated successfully\n", keyFileName)
	}
	fmt.Println("Private key correctly split and stored!!")
}

func init() {
	rootCmd.AddCommand(generateKeySplitCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// generateKeyfileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// generateKeyfileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	generateKeySplitCmd.Flags().StringVarP(&kdfNew, "kdf", "", "scrypt", "--kdf preferredKDF")
	generateKeySplitCmd.Flags().IntVarP(&numShares, "shares", "s", 3, "--shares \tTotal number of shares of the secret")
	generateKeySplitCmd.Flags().IntVarP(&minShares, "threshold", "t", 2, "--threshold  \tSecret recovery threshold")
	generateKeySplitCmd.Flags().StringVarP(&genFilenameBase, "filename", "f", "splitkeyfile", "--filename \tFile base name")
	generateKeySplitCmd.Flags().StringVarP(&ethkeyStr, "ethkey", "e", "", "--ethkey \tSecret to be split")
}

func (ps *sharePrishare) Serialize() (buf []byte) {

	uint_I := uint64(ps.I) //byte(I)
	buf = make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint_I)

	temp_buf2, err := ps.V.MarshalBinary()
	if err != nil {
		fmt.Println(err)
		return
	}
	buf = append(buf, temp_buf2...)
	return
}

func (ps *sharePrishare) Deserialize(btes []byte) (*sharePrishare, error) {
	if len(btes) != 40 {
		return nil, fmt.Errorf("Wrong buffer length", len(btes))
	}
	ps.I = int(binary.LittleEndian.Uint64(btes[:8]))
	ps.V = pairing.NewSuiteBn256().G2().Scalar()
	ps.V.UnmarshalBinary(btes[8:])
	return ps, nil
}

func (ps *sharePrishare) MarshalJSON() ([]byte, error) {
	bt := ps.Serialize()
	return []byte(hex.EncodeToString(bt)), nil
}

func (ps *sharePrishare) UnmarshalJSON(in []byte) error {
	ser, err := hex.DecodeString(string(in))
	if err != nil {
		return err
	}
	ps.Deserialize(ser)
	return nil
}

func DeserializePriShare(hexstring string) (*share.PriShare, error) {
	buf, err := hex.DecodeString(hexstring)
	if err != nil {
		return nil, err
	}
	tps := new(sharePrishare)
	tps, err = tps.Deserialize(buf)
	ps := share.PriShare(*tps)
	return &ps, err
}

func SerializePriShare(shr share.PriShare) []byte {
	tps := sharePrishare(shr)
	buf := tps.Serialize()
	return []byte(hex.EncodeToString(buf))
}
