package terraform

import (
	"os"
	"testing"
)

func TestUnmarshallValidTfJson(t *testing.T) {
	fileName := "./data/terraform-valid.json"
	buf, err := os.ReadFile(fileName)

	if err != nil {
		t.Fatalf("Unexpected error %s reading file %s ", fileName, err)
	}

	services, err := UnmarshalTerraformPlannedInput(buf)
	if err != nil {
		t.Fatalf("Unexpected error %s unarshalling %s ", fileName, err)
	}

	if len(services) != 1 {
		t.Errorf("Length of services should be %d, got %d", 1, len(services))
	}

	if services[0].Acls[0].Name != "foo_acl" {
		t.Errorf("Acl name want %s, got %s", services[0].Acls[0].Name, "foo_acl")
	}

	if services[0].Backends[0].Name != "foo_backend" {
		t.Errorf("Backend name want %s, got %s", services[0].Backends[0].Name, "foo_backend")
	}

	if services[0].Dictionaries[0].Name != "foo_dictionary" {
		t.Errorf("Dictionary name want %s, got %s", services[0].Dictionaries[0].Name, "foo_dictionary")
	}
}

func TestUnmarshallInValidTfJson(t *testing.T) {
	fileName := "./data/terraform-invalid.json"
	buf, err := os.ReadFile(fileName)

	if err != nil {
		t.Fatalf("Unexpected error %s reading file %s ", fileName, err)
	}

	_, err = UnmarshalTerraformPlannedInput(buf)
	if err == nil {
		t.Fatalf("Expected error when unarshalling tf %s ", fileName)
	}
}

func TestUnmarshallInWithoutVCLTfJson(t *testing.T) {
	fileName := "./data/terraform-without-vcl.json"
	buf, err := os.ReadFile(fileName)

	if err != nil {
		t.Fatalf("Unexpected error %s reading file %s ", fileName, err)
	}

	services, err := UnmarshalTerraformPlannedInput(buf)
	if err != nil {
		t.Fatalf("Unexpected error when unarshalling tf %s ", fileName)
	}

	if len(services) != 1 {
		t.Errorf("Length of services should be %d, got %d", 1, len(services))
	}
}
