package terraform

import (
	"context"
	"os"
	"testing"
)

func TestStuff(t *testing.T) {

	fileName := "./data/terraform-valid.json"
	buf, err := os.ReadFile(fileName)

	if err != nil {
		t.Fatalf("Unexpected error %s reading file %s ", fileName, err)
	}

	services, err := UnmarshalTerraformPlannedInput(buf)
	if err != nil {
		t.Fatalf("Unexpected error %s unarshalling %s ", fileName, err)
	}

	f := NewTerraformFetcher(services)

	acls, _ := f.Acls(context.TODO())
	if len(acls) != 1 {
		t.Errorf("Length of ACLs should be %d, got %d", 1, len(acls))
	}

	if acls[0].Name != "foo_acl" {
		t.Errorf("Acl name want %s, got %s", acls[0].Name, "foo_acl")
	}

	backends, _ := f.Backends(context.TODO())
	if len(backends) != 1 {
		t.Errorf("Length of Backends should be %d, got %d", 1, len(backends))
	}

	if backends[0].Name != "foo_backend" {
		t.Errorf("Backend name want %s, got %s", backends[0].Name, "foo_backend")
	}

	dictionaries, _ := f.Dictionaries(context.TODO())
	if len(dictionaries) != 1 {
		t.Errorf("Length of dictionaries should be %d, got %d", 1, len(dictionaries))
	}

	if dictionaries[0].Name != "foo_dictionary" {
		t.Errorf("Dictionary name want %s, got %s", dictionaries[0].Name, "foo_dictionary")
	}

}
