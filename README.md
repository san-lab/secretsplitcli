A simple CLI to generate Shamir Secret Shares of a bn256 BLS private key
Based on Corba.The fole format is adapted from Ethereum key files.
The cryptographic part depends on kyber

Usage:
  secretsplitcli [command]

Available Commands:
  generateKeySplit Generates shamir secret shares of a private key
  generateKeyfile  Generate a new keyfile
  help             Help about any command
  readKeyfile      Read an Ethereum key file
  recreateSplitKey Read an Ethereum key file

Flags:
      --config string   config file (default is $HOME/.goethkey.yaml)
  -h, --help            help for secretsplitcli
  -v, --verbose         verbose output

Use "secretsplitcli [command] --help" for more information about a command.
### Explicit libraries needed to execute.
go get github.com/google/uuid
go get github.com/mitchellh/go-homedir
go get github.com/spf13/cobra
go get github.com/spf13/viper

