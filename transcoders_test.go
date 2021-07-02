package multiaddr

import "testing"

func TestGarlicBridge(t *testing.T) {
	// Simple code and decode
	fS := "7|7|6|6|2|2"
	B, err := garlicBridgeStB(fS)
	if err != nil {
		t.Error(err)
	}
	err = garlicBridgeValidate(B)
	if err != nil {
		t.Error(err)
	}
	S, err := garlicBridgeBtS(B)
	if err != nil {
		t.Error(err)
	}
	if fS != S {
		t.Fatalf("Got %v instead of %v.", S, fS)
	}

	shouldFail := [][]byte{ // sample (7|7|6|6|2|2) : []byte{0xFF,0x6A},
		[]byte{0xFF, 0xEA},
		[]byte{0xFF, 0x7A},
		[]byte{0xFF, 0x7E},
		[]byte{0xFF, 0x7B},
		[]byte{0xFC, 0x4A},
		[]byte{0xFE, 0x0A},
		[]byte{0xFE, 0xDE},
		[]byte{0xFE, 0xDB},
		[]byte{0xFF, 0x7B, 0xFF},
		[]byte{0xFF},
	}
	for _, e := range shouldFail {
		S, err = garlicBridgeBtS(e)
		if err == nil || S != "" {
			t.Fatalf("Should fail but works with %v, and got %v.", e, S)
		}
	}
}
