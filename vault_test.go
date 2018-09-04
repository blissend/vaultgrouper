package vault

import (
	"testing"
)

// TestSliceExists checks ability to check item existance in slice
func TestSliceExists(t *testing.T) {
	// Setup values
	data := make([]string, 3)
	data[0] = "carlin"
	data[1] = "is"
	data[2] = "cool" // :D

	if false == SliceExists(data, "cool") {
		t.Fatalf("Slice test should have found item")
	}
	if true == SliceExists(data, "bad") {
		t.Fatalf("Slice test should NOT have found item")
	}
}

// TestCall checks for ability to make each call
func TestCall(t *testing.T) {
	// Setup vault/payload
	v := Vault{}
	data := make(map[string]interface{})
	data["username"] = "fancypants"
	data["carlin"] = "cool" // :D
	client, err := v.Client()
	if err != nil {
		t.Fatalf("Could not setup Vault client")
	}
	client.SetToken("myroot")

	resp, err := Call(client, "write", "app/test", data)
	resp, err = Call(client, "read", "app/test", nil)
	if resp.Data["carlin"] != "cool" {
		t.Fatalf("Sample data failed modification")
	}
}
