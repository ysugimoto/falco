package terraform

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestUnmarshallValidTfJson(t *testing.T) {
	fileName := "./data/terraform-valid.json"
	buf, err := os.ReadFile(fileName)

	if err != nil {
		t.Fatalf("Unexpected error %s reading file %s ", fileName, err)
	}

	services, err := unmarshalTerraformPlannedInput(buf)
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

	_, err = unmarshalTerraformPlannedInput(buf)
	if err == nil {
		t.Fatalf("Expected error when unarshalling tf %s ", fileName)
	}
}

func TestUnmarshalWithAclEntryAndDictionaryItemsTsJson(t *testing.T) {
	fileName := "./data/terraform-entry-items.json"
	buf, err := os.ReadFile(fileName)

	if err != nil {
		t.Fatalf("Unexpected error %s reading file %s ", fileName, err)
	}

	services, err := unmarshalTerraformPlannedInput(buf)
	if err != nil {
		t.Fatalf("Unexpected error when unarshalling tf %s ", fileName)
	}

	if len(services) != 1 {
		t.Errorf("Length of services should be %d, got %d", 1, len(services))
	}

	aclExpects := &Acl{
		Name: "test_acl",
		Entries: []*AclEntry{
			{
				Comment: "Entry-1",
				Ip:      "127.0.0.1",
				Negated: true,
				Subnet:  "24",
			},
			{
				Comment: "Entry-2",
				Ip:      "192.0.2.0",
				Negated: false,
				Subnet:  "32",
			},
		},
	}
	if diff := cmp.Diff(aclExpects, services[0].Acls[0]); diff != "" {
		t.Errorf("Unmarshalled ACL mismatch, diff=%s", diff)
	}

	dictExpects := &Dictionary{
		Name:      "example",
		WriteOnly: false,
		Items: []*DictionaryItem{
			{Key: "foo", Value: "bar"},
			{Key: "lorem", Value: "ipsum"},
		},
	}
	if diff := cmp.Diff(dictExpects, services[0].Dictionaries[0]); diff != "" {
		t.Errorf("Unmarshalled Dictionary mismatch, diff=%s", diff)
	}
}
