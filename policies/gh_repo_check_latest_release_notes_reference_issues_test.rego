package compliance_framework.change_control_release_notes_reference_issue

test_satisfies_exists if {
  inp := {"last_release": {"body": "## What's Changed\r\n* Support idempotent dashboard imports by @chris-cmsoft in https://github.com/compliance-framework/api/pull/280\r\n\r\n\r\n**Full Changelog**: https://github.com/compliance-framework/api/compare/v0.4.9...v0.4.10"}}
  violations := { v | violation[v] with input as inp }
  count(violations) == 0
}

test_no_release_violation if {
  inp := {}
  violations := violation[v] with input as inp
  count(violation) == 1
  v.remarks == "No releases available for this repository."
}

test_release_without_references_violation if {
  inp := {"last_release": {"body": "Body with release notes and no refs"}}
  violations := violation[v] with input as inp
  count(violation) == 1
  v.remarks == "Latest Release Notes do not reference any work."
}