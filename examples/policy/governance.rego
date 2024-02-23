package governance

default allow = false

provenance_attestations := [input[i] | input[i].predicateType == "https://slsa.dev/provenance/v0.2"]

sbom_attestations :=[input[i] | input[i].predicateType == "https://spdx.dev/Document"]

vuln_attestations := [input[i] | input[i].predicateType == "https://cosign.sigstore.dev/attestation/vuln/v1"]

pr_attestations := [input[i] | input[i].predicateType == "https://github.com/michaelvl/gha-reusable-workflows/pr-provenance" ]

allow {
    violations := provenance_violations | sbom_violations | vuln_violations | pr_violations
    print(violations)
    count(violations) == 0
}

provenance_violations[msg] {
    count(provenance_attestations) == 0
    msg:= "no provenance attestation"
}

sbom_violations[msg] {
    count(sbom_attestations) == 0
    msg:= "no sbom attestation"
}

vuln_violations[msg] {
    count(vuln_attestations) == 0
    msg:= "no vuln attestation"
}

pr_violations[msg] {
    count(pr_attestations) == 0
    msg:= "no pr attestation"
}
