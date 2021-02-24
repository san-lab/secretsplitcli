package goethkey

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
)

func Serialize(ps *share.PriShare) (buf []byte, err error) {
	uint_I := uint64(ps.I) //byte(I)
	buf = make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint_I)
	temp_buf2, err := ps.V.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf = append(buf, temp_buf2...)
	return
}

func Deserialize(btes []byte) (*share.PriShare, error) {
	if len(btes) != 40 {
		return nil, errors.New("Incorrect size for the bytearray to be deserialized")
	}
	ps := new(share.PriShare)
	ps.I = int(binary.LittleEndian.Uint64(btes[:8]))
	ps.V = pairing.NewSuiteBn256().G2().Scalar()
	ps.V.UnmarshalBinary(btes[8:])
	return ps, nil
}

func MarshalHEX(ps *share.PriShare) ([]byte, error) {
	bt, err := Serialize(ps)
	if err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(bt)), nil
}

func UnmarshalHEX(in []byte) (*share.PriShare, error) {
	ser, err := hex.DecodeString(string(in))
	if err != nil {
		return nil, err
	}
	return Deserialize(ser)
}
