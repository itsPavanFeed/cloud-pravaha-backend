# Platform guide

## Organisation, entities and business units

A tenant is one customer organisation with its own tenant plane (API, database, Temporal, bucket, runners). Inside a tenant, entities group business units (BUs): an entity is a company or product line, and a BU is a team. Stacks and environments belong to exactly one BU.

Tenant roles: tenant_admin (manages the tenant), finops and security (approval steps for the whole tenant), auditor (read-only everywhere, including audit). Scoped roles granted on an entity or a BU: admin, manager, developer, viewer. Roles granted on an entity apply to every BU in it. Developers create stacks and start runs in their BUs. Managers also approve runs. BU admins manage environments. Viewers only read.

## Cloud connections and environments

A cloud connection is a tenant-level integration with one AWS account, GCP project or Azure subscription. Tenant admins create it and scope it to entities. Connections use keyless federation: AWS IAM roles assumed with web identity, GCP Workload Identity Federation with service account impersonation, Azure workload identity federation. No long-lived cloud keys are stored. A connection can name a separate read-only identity for plans (plan_role_arn, plan_service_account_email, plan_client_id), so plans never hold write credentials.

An environment binds a BU to a connection and a tier (prod or nonprod). It also sets the runner pool, whether destroys are allowed and the maximum number of destroys per run. A stack's environment decides which cloud its modules must target: AWS modules only work in AWS environments, and modules in the common folder work everywhere.

## Writing a stack

A stack is JSON, never HCL. It lists module instances from the approved catalog, the inputs for each, and the outputs to expose:

```json
{
  "modules": [
    { "name": "network", "module": "aws-vpc", "inputs": { "name": "payments", "cidr": "10.20.0.0/16" } },
    { "name": "db", "module": "aws-rds", "inputs": { "identifier": "payments", "subnet_ids": { "$ref": "network.private_subnets" } } }
  ],
  "outputs": [ { "name": "db_endpoint", "module": "db", "output": "db_instance_endpoint" } ]
}
```

Rules: instance names are lowercase snake_case. `module` is a catalog ID. `version` is optional and must be an approved version; it defaults to the latest approved one. Only the inputs the catalog lists may be set, and values must satisfy their type, pattern, allowed values and ranges. Enforced baseline inputs cannot be set at all. A value of the form {"$ref": "instance.output"} wires one module's catalog-declared output into another module's input. Secrets never go into stacks: modules that need a password generate it or use the cloud's secret manager (for example, aws-rds uses a Secrets Manager master password).

## Runs, risk and approvals

Every change is a run. The runner plans first, and the plan is classified by risk. Risk is raised by:

- a prod environment
- destroys and replacements (high)
- identity and access changes (high)
- network exposure changes (high in prod)
- imports
- in-place changes and large change sets
- the estimated monthly cost increase

Only additions in a non-production environment are low risk. Low risk needs a manager. Medium risk needs a manager and finops. High risk needs a manager, finops and security. Tenant admins or security can change these thresholds in the risk policy. Whoever started a run cannot approve it. Applies use the exact saved plan. If the configuration changes after planning, the plan is stale and must be re-run.

Cost: each plan shows an approximate monthly delta from list prices for fixed-cost resources (clusters, NAT gateways, database and VM sizes). Usage-based charges are not included.

Policies: built-in rules block open ingress from 0.0.0.0/0, forbidden resource types, destroys beyond the environment's limit and imports that would destroy. Tenants can add OPA (Rego) policy sets in package pravaha.policy that emit deny messages. Hard violations block the run. Advisory ones are shown to approvers.

## Importing existing resources (backporting)

To bring existing cloud resources under management, add `imports` to a stack. Each import names an address inside one of the stack's module instances and the cloud ID, for example {"to": "module.bucket.aws_s3_bucket.this[0]", "id": "acme-legacy-artifacts"}. The plan imports the resources instead of creating them. An import that would also destroy or replace a resource is blocked. After a successful apply, remove the imports.

## Drift

Stacks can schedule drift checks: refresh-only plans that compare real infrastructure with state. Drift is shown on the stack. With auto-remediation on, a corrective plan is queued, and it still goes through approvals.

## Git-managed stacks (contracts repository)

Each tenant can connect a contracts repository on GitHub or GitLab. The tenant plane pulls it. Every stacks/<name>.json file there becomes a Git-managed stack, and those stacks cannot be edited in the UI. A push can plan automatically (auto_plan). Low-risk changes can be applied without a human (auto_apply_low_risk). Everything else waits for approvals as usual.

## Adding a module to the catalog

The catalog lives in the cloud-pravaha-modules repository. It contains only public registry modules, pinned to exact versions, with a security baseline for each. To request a module, open a pull request that adds a JSON entry under catalog/modules/<cloud>/. The folder's code owners review it. Custom modules and Git or HTTP module sources are not allowed.
