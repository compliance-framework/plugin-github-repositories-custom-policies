package compliance_framework.change_control_release_notes_reference_issue

latest := input.last_release

violation[{"remarks": "No releases available for this repository."}] if {
    not release_present
}

violation[{"remarks": "Latest Release Notes do not reference any work."}] if {
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

    some i
    pattern := patterns[i]
    regex.match(pattern, trimmed)
}

# Patterns for “tracked work”:
patterns := [
    # - GitHub PR/issue: #123
    "#[0-9]+",
    # - JIRA-style tickets: ABC-123, PROJ-42, etc.
    "[A-Z][A-Z0-9]+-[0-9]+",
    #Reference to a Github Pull Request
    # A full domain followed by anything (path)
    # followed by github pull API
    "https://[a-z0-9-.]+/.*/pull/[0-9]+"
]

title := "Release notes reference tracked work"
description := "The latest release notes must reference at least one tracked change, such as a pull request or ticket. Expected shape: input.LatestRelease.notes containing patterns like '#123' or 'ABC-123'."
