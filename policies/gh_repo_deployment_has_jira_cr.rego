package compliance_framework.deployment_has_jira_cr

import future.keywords.if
import future.keywords.in

title := "Production deployments must reference Jira change requests"
description := "All production deployments must have at least one status that references a Jira CR ticket (e.g., CR-123, TSTCHG-1) in the description or log_url."

risk_templates := [{
  "name": "Production deployment lacks Jira change request reference",
  "title": "Unauthorized or Untracked Change Deployed to Production",
  "statement": "Production deployments without a linked Jira change request (CR) ticket indicate that the change may not have gone through the formal change management process. Untracked production changes bypass risk assessment, approval gates, and rollback planning. This increases the probability of introducing instability, security regressions, or compliance violations into the production environment without organizational oversight or an auditable approval trail.",
  "likelihood_hint": "moderate",
  "impact_hint": "high",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-693",
      "title": "Protection Mechanism Failure",
      "url": "https://cwe.mitre.org/data/definitions/693.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-284",
      "title": "Improper Access Control",
      "url": "https://cwe.mitre.org/data/definitions/284.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1059",
      "title": "Incomplete Documentation",
      "url": "https://cwe.mitre.org/data/definitions/1059.html"
    }
  ],
  "remediation": {
    "title": "Enforce Jira CR ticket references in all production deployments",
    "description": "Update deployment pipelines to require a Jira CR ticket reference in the deployment status description or log URL before any production deployment can proceed. Gate the deployment workflow on the presence of a valid CR reference.",
    "tasks": [
      { "title": "Update the deployment pipeline to accept a CR ticket parameter and include it in deployment status" },
      { "title": "Add a pre-deployment gate that validates a CR ticket reference is present and matches the expected pattern" },
      { "title": "Create a retroactive Jira CR for any untracked deployment and link it to the deployment record" },
      { "title": "Define and communicate the change management policy requiring CRs for all production deployments" },
      { "title": "Configure Jira to require CR ticket creation and approval as a prerequisite to production deployment approvals" }
    ]
  }
}]

jira_ticket_pattern := "[A-Z][A-Z0-9]+-[0-9]+"

violation[{"id": "deployment_missing_jira_cr", "remarks": remarks}] if {
	deployment_with_statuses := input.deployments[_]
	deployment := deployment_with_statuses.deployment
	is_production_deployment(deployment)
	not has_jira_reference_in_statuses(deployment_with_statuses.statuses)
	
	latest_state := get_latest_state(deployment_with_statuses.statuses)
	remarks := sprintf("Deployment %d to %s (state: %s) does not reference a Jira CR in any deployment status", [deployment.id, deployment.environment, latest_state])
}

is_production_deployment(deployment) if {
	lower(deployment.environment) == "production"
}

is_production_deployment(deployment) if {
	lower(deployment.environment) == "prod"
}

has_jira_reference_in_statuses(statuses) if {
	status := statuses[_]
	has_jira_reference_in_status(status)
}

has_jira_reference_in_status(status) if {
	description := status.description
	description != null
	description != ""
	regex.match(jira_ticket_pattern, description)
}

has_jira_reference_in_status(status) if {
	log_url := status.log_url
	log_url != null
	log_url != ""
	regex.match(jira_ticket_pattern, log_url)
}

get_latest_state(statuses) := state if {
	count(statuses) > 0
	state := statuses[0].state
} else := "unknown"
