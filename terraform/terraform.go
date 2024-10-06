package terraform

import (
	"encoding/json"

	"github.com/pkg/errors"
)

const (
	fastlyTerraformProviderName = "registry.terraform.io/fastly/fastly"
	fastlyVCLServiceType        = "fastly_service_vcl"
	fastlyVCLServiceTypeV1      = "fastly_service_v1"
)

// Terraform planned input struct
// This struct could be unmarshled from input of `terraform show -json [planned json]
type TerraformVcl struct {
	Content string
	Main    bool
	Name    string
}

type TerraformAcl struct {
	Name string
}

type TerraformDictionary struct {
	Name string
}

type TerraformSnippet struct {
	Name     string
	Type     string
	Content  string
	Priority int64
}

type TerraformLoggingEndpoint struct {
	Name string
}

// TODO(davinci26): We can unmarshall all the properties from the TF file
// and lint them to make sure they have sane values.
type TerraformBackend struct {
	Name    string
	Shield  *string
	Address *string
}

type TerraformDirector struct {
	Type     int
	Name     string
	Backends []string
	Retries  *int
	Quorum   *int
}

type FastlyService struct {
	Name             string
	Vcls             []*TerraformVcl
	Backends         []*TerraformBackend
	Acls             []*TerraformAcl
	Dictionaries     []*TerraformDictionary
	Directors        []*TerraformDirector
	Snippets         []*TerraformSnippet
	LoggingEndpoints []string
}

type FastlyServiceValues struct {
	Name       string                 `json:"name"`
	Vcl        []*TerraformVcl        `json:"vcl"`
	Acl        []*TerraformAcl        `json:"acl"`
	Backend    []*TerraformBackend    `json:"backend"`
	Director   []*TerraformDirector   `json:"director"`
	Dictionary []*TerraformDictionary `json:"dictionary"`
	Snippets   []*TerraformSnippet    `json:"snippet"`

	// Various kinds of realtime logging endpoints
	LoggingBigQuerty     []*TerraformLoggingEndpoint `json:"logging_bigqeury"`
	LoggingBlobStorage   []*TerraformLoggingEndpoint `json:"logging_blobstorage"`
	LoggingCloudFiles    []*TerraformLoggingEndpoint `json:"logging_cloudfiles"`
	LoggingDatadog       []*TerraformLoggingEndpoint `json:"logging_datadog"`
	LoggingDigitalOpean  []*TerraformLoggingEndpoint `json:"logging_digitalocean"`
	LoggingElasticsearch []*TerraformLoggingEndpoint `json:"logging_elasticsearch"`
	LoggingFtp           []*TerraformLoggingEndpoint `json:"logging_ftp"`
	LoggingGcs           []*TerraformLoggingEndpoint `json:"logging_gcs"`
	LoggingGooglePubSub  []*TerraformLoggingEndpoint `json:"logging_googlepubsub"`
	LoggingHeroku        []*TerraformLoggingEndpoint `json:"logging_heroku"`
	LoggingHttps         []*TerraformLoggingEndpoint `json:"logging_https"`
	LoggingKafka         []*TerraformLoggingEndpoint `json:"logging_kafka"`
	LoggingKinesis       []*TerraformLoggingEndpoint `json:"logging_kinesis"`
	LoggingLogEntries    []*TerraformLoggingEndpoint `json:"logging_logentries"`
	LoggingLoggly        []*TerraformLoggingEndpoint `json:"logging_loggly"`
	LoggingLogShuttle    []*TerraformLoggingEndpoint `json:"logging_logshuttle"`
	LoggingNewRelic      []*TerraformLoggingEndpoint `json:"logging_newrelic"`
	LoggingOpenStack     []*TerraformLoggingEndpoint `json:"logging_openstack"`
	LoggingPaperTrail    []*TerraformLoggingEndpoint `json:"logging_papertrail"`
	LoggingS3            []*TerraformLoggingEndpoint `json:"logging_s3"`
	LoggingScalyr        []*TerraformLoggingEndpoint `json:"logging_scalyr"`
	LoggingSftp          []*TerraformLoggingEndpoint `json:"logging_sftp"`
	LoggingSplunk        []*TerraformLoggingEndpoint `json:"logging_splunk"`
	LoggingSumoLogic     []*TerraformLoggingEndpoint `json:"logging_sumologic"`
	LoggingSyslog        []*TerraformLoggingEndpoint `json:"logging_syslog"`
}

type TerraformPlannedResource struct {
	ProviderName string          `json:"provider_name"`
	Type         string          `json:"type"`
	Values       json.RawMessage `json:"values"`
}

type TerraformPlannedInput struct {
	PlannedValues *struct {
		RootModule *struct {
			Resources    []*TerraformPlannedResource `json:"resources"`
			ChildModules []*struct {
				Resources []*TerraformPlannedResource `json:"resources"`
			} `json:"child_modules"`
		} `json:"root_module"`
	} `json:"planned_values"`
}

func UnmarshalTerraformPlannedInput(buf []byte) ([]*FastlyService, error) {
	var root TerraformPlannedInput

	if err := json.Unmarshal(buf, &root); err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal stdin input")
	}

	if root.PlannedValues == nil {
		return nil, errors.New(`Input does not seem to terraform planned JSON: "planned_values" field does not exist`)
	}

	if root.PlannedValues.RootModule == nil {
		return nil, errors.New(`Input does not seem to terraform planned JSON: "root_module" field does not exist`)
	}

	var services []*FastlyService
	var serviceValues *FastlyServiceValues
	// Case: service is declared in root module
	if len(root.PlannedValues.RootModule.Resources) > 0 {
		for _, v := range root.PlannedValues.RootModule.Resources {
			if !isFastlyVCLServiceResource(v) {
				continue
			}

			if err := json.Unmarshal(v.Values, &serviceValues); err != nil {
				return nil, errors.Wrap(err, "Failed to unmarshal values")
			}

			services = append(services, &FastlyService{
				Name:             serviceValues.Name,
				Vcls:             serviceValues.Vcl,
				Acls:             serviceValues.Acl,
				Backends:         serviceValues.Backend,
				Dictionaries:     serviceValues.Dictionary,
				Directors:        serviceValues.Director,
				Snippets:         serviceValues.Snippets,
				LoggingEndpoints: factoryLoggingEndpoints(serviceValues),
			})
		}
	}

	// Case: service is declared in child module
	for _, v := range root.PlannedValues.RootModule.ChildModules {
		for _, v := range v.Resources {
			if !isFastlyVCLServiceResource(v) {
				continue
			}

			if err := json.Unmarshal(v.Values, &serviceValues); err != nil {
				return nil, errors.Wrap(err, "Failed to unmarshal values")
			}

			services = append(services, &FastlyService{
				Name:             serviceValues.Name,
				Vcls:             serviceValues.Vcl,
				Acls:             serviceValues.Acl,
				Backends:         serviceValues.Backend,
				Dictionaries:     serviceValues.Dictionary,
				Directors:        serviceValues.Director,
				Snippets:         serviceValues.Snippets,
				LoggingEndpoints: factoryLoggingEndpoints(serviceValues),
			})
		}
	}

	if len(services) == 0 {
		return nil, errors.New(`Fastly service does not exist. Did you plan with fastly terraform provider?`)
	}

	return services, nil
}

func isFastlyVCLServiceResource(r *TerraformPlannedResource) bool {
	return r.ProviderName == fastlyTerraformProviderName &&
		(r.Type == fastlyVCLServiceType || r.Type == fastlyVCLServiceTypeV1)
}

func factoryLoggingEndpoints(values *FastlyServiceValues) []string {
	var endpoints []string
	for _, v := range values.LoggingBigQuerty {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingBlobStorage {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingCloudFiles {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingDatadog {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingDigitalOpean {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingElasticsearch {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingFtp {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingGcs {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingGooglePubSub {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingHeroku {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingHttps {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingKafka {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingKinesis {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingLogEntries {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingLoggly {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingLogShuttle {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingNewRelic {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingOpenStack {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingPaperTrail {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingS3 {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingScalyr {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingSplunk {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingSumoLogic {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingSyslog {
		endpoints = append(endpoints, v.Name)
	}
	return endpoints
}
