package compliance_framework.deployment_has_jira_cr_test

import data.compliance_framework.deployment_has_jira_cr as policy

test_violation_when_production_deployment_has_no_jira_reference if {
	inp := {"deployments": [{
		"deployment": {
			"id": 12345,
			"environment": "production",
			"ref": "main",
		},
		"statuses": [{
			"state": "pending",
			"description": "Deployment started",
			"log_url": null,
		}],
	}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_prod_deployment_has_no_jira_reference if {
	inp := {"deployments": [{
		"deployment": {
			"id": 12346,
			"environment": "prod",
			"ref": "main",
		},
		"statuses": [{
			"state": "success",
			"description": "Deployment completed",
			"log_url": "",
		}],
	}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_production_deployment_has_jira_in_description if {
	inp := {"deployments": [{
		"deployment": {
			"id": 12347,
			"environment": "production",
			"ref": "main",
		},
		"statuses": [{
			"state": "in_progress",
			"description": "Jira CR: TSTCHG-123",
			"log_url": null,
		}],
	}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_production_deployment_has_jira_in_log_url if {
	inp := {"deployments": [{
		"deployment": {
			"id": 12348,
			"environment": "production",
			"ref": "main",
		},
		"statuses": [{
			"state": "success",
			"description": "Deployment completed",
			"log_url": "https://jira.example.com/browse/CR-456",
		}],
	}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_non_production_deployment_has_no_jira if {
	inp := {"deployments": [{
		"deployment": {
			"id": 12349,
			"environment": "staging",
			"ref": "develop",
		},
		"statuses": [{
			"state": "success",
			"description": "Staging deployment",
			"log_url": null,
		}],
	}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_multiple_statuses_one_has_jira if {
	inp := {"deployments": [{
		"deployment": {
			"id": 12350,
			"environment": "production",
			"ref": "main",
		},
		"statuses": [
			{
				"state": "pending",
				"description": "Deployment started",
				"log_url": null,
			},
			{
				"state": "in_progress",
				"description": "Jira CR: PROJ-789",
				"log_url": "https://jira.example.com/browse/PROJ-789",
			},
			{
				"state": "success",
				"description": "Deployment completed",
				"log_url": null,
			},
		],
	}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_multiple_deployments_one_missing_jira if {
	inp := {"deployments": [
		{
			"deployment": {
				"id": 12351,
				"environment": "production",
				"ref": "main",
			},
			"statuses": [{
				"state": "success",
				"description": "Jira CR: CR-100",
				"log_url": null,
			}],
		},
		{
			"deployment": {
				"id": 12352,
				"environment": "production",
				"ref": "main",
			},
			"statuses": [{
				"state": "success",
				"description": "No reference here",
				"log_url": null,
			}],
		},
	]}

	violations := policy.violation with input as inp
	count(violations) == 1
}
