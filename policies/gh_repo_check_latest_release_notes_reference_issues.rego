package compliance_framework.change_control_release_notes_reference_issue

latest := input.last_release

risk_templates := [{
	"name": "Release notes do not reference tracked work",
	"title": "Untracked Changes in Releases Create Audit and Compliance Gaps",
	"statement": "Release notes that do not reference pull requests, issues, or change tickets make it impossible to trace released changes back to approved work items. This breaks the audit trail required for change management compliance, prevents reviewers from confirming that only approved changes were included, and hinders post-release incident investigation.",
	"likelihood_hint": "moderate",
	"impact_hint": "moderate",
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-1059",
			"title": "Incomplete Documentation",
			"url": "https://cwe.mitre.org/data/definitions/1059.html",
		},
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-693",
			"title": "Protection Mechanism Failure",
			"url": "https://cwe.mitre.org/data/definitions/693.html",
		},
	],
	"remediation": {
		"title": "Include tracked work references in all release notes",
		"description": "Ensure every release notes entry references at least one tracked work item (GitHub issue/PR number, Jira ticket, or equivalent) to maintain a complete audit trail from requirement to release.",
		"tasks": [
			{"title": "Update existing release notes to reference the associated PRs or tickets"},
			{"title": "Adopt a release notes template that includes a 'Changes' section with issue/PR references"},
			{"title": "Use GitHub's auto-generated release notes feature to pull in PR references automatically"},
			{"title": "Add a CI check or release gate that validates release notes contain at least one tracked reference"},
			{"title": "Enforce a conventional commit or PR title standard that makes change traceability automatic"},
		],
	},
}]

violation[{"id": "no_release_present", "remarks": "No releases available for this repository."}] if {
	not release_present
}

violation[{"id": "release_notes_no_tracked_work", "remarks": "Latest Release Notes do not reference any work."}] if {
	release_present
	not release_notes_reference_issue
}

release_present if {
	latest != null
	notes := latest.body
	notes != null
	trim_space(notes) != ""
}

release_notes_reference_issue if {
	notes := latest.body
	trimmed := trim_space(notes)
	trimmed != ""

	some pattern in patterns
	regex.match(pattern, trimmed)
}

# Patterns for “tracked work”:
patterns := [
	# - GitHub PR/issue: #123
	"#[0-9]+",
	# - JIRA-style tickets: ABC-123, PROJ-42, etc.
	"[A-Z][A-Z0-9]+-[0-9]+",
	# Reference to a Github Pull Request
	# A full domain followed by anything (path)
	# followed by github pull API
	"https://[a-z0-9-.]+/.*/pull/[0-9]+",
]

title := "Release notes reference tracked work"
description := "The latest release notes must reference at least one tracked change, such as a pull request or ticket. Expected shape: input.LatestRelease.notes containing patterns like '#123' or 'ABC-123'."
