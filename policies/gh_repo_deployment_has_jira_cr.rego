package compliance_framework.deployment_has_jira_cr

import future.keywords.if
import future.keywords.in

title := "Production deployments must reference Jira change requests"
description := "All production deployments must have at least one status that references a Jira CR ticket (e.g., CR-123, TSTCHG-1) in the description or log_url."

jira_ticket_pattern := "[A-Z][A-Z0-9]+-[0-9]+"

violation[{"remarks": remarks}] if {
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
