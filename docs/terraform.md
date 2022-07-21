# Run with terraform

`falco` supports linting for [terraform](https://www.terraform.io/) planned result which is used [Fastly Provider](https://github.com/fastly/terraform-provider-fastly).

## Usage

terraform can output plan result to file and show as JSON. `falco` could retrieve planned VCL definition from it.
To lint them, run `falco terraform` subcommand with providing JSON as stdin:

```shell
# Plan terraform and output to file using fastly terraform provider
terraform plan -out planned.out

# Show JSON and pipe to the falco
terraform show -json planned.out | falco terraform

# If the linter has passed, apply it!
terraform apply "planned.out"
```

## How it work

terraform plan result has specific field about built VCL, then falco could retrieve its fields internally and lint them.
You MUST include Fastly Provider planned result in output either root module or child module.

Note than you can define multiple custom VCLs in `vcl` field in `fastly_service_vcl` resource, but we only lint main module which is defined with `main = true` initially, don't lint other vcl definition until thy are included
To lint them, ensure they are included from main (or other) VCL.
