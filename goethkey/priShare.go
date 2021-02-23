package goethkey

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
)

type sharePrishare share.PriShare

func PriShareEmpty() (*sharePrishare) {
	return new(sharePrishare)
}

func PriShare(I int, V kyber.Scalar) (sharePrishare) {
	return sharePrishare{I, V}
}

func (ps *sharePrishare) Serialize() (buf []byte, err error) {

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

func (ps *sharePrishare) Deserialize(btes []byte) (*sharePrishare, error) {
	if len(btes) != 40 {
		return nil, errors.New("Incorrect size for the bytearray to be deserialized")
	}
	ps.I = int(binary.LittleEndian.Uint64(btes[:8]))
	ps.V = pairing.NewSuiteBn256().G2().Scalar()
	ps.V.UnmarshalBinary(btes[8:])
	return ps, nil
}

func (ps *sharePrishare) MarshalJSON() ([]byte, error) {
	bt, err := ps.Serialize()
	if err != nil {
		return nil, err
	}
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
