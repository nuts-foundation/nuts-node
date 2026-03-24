# DCQL — Digital Credentials Query Language

This package implements a subset of the Digital Credentials Query Language (DCQL)
as specified in [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html),
sections 6.1, 6.3, and 7.

## Purpose

DCQL is used in this codebase for **deterministic credential selection** from the wallet.
When multiple credentials of the same type exist (e.g., multiple PatientEnrollmentCredentials
for different patients), the EHR provides a DCQL credential query to specify which one to present.

This differs from the spec's primary use case, where DCQL is used by a Verifier to request
selective disclosure from a Wallet. In that context, the `values` parameter is a best-effort
privacy hint — the spec states: *"Verifiers MUST treat restrictions expressed using values as
a best-effort way to improve user privacy, but MUST NOT rely on it for security checks."*

In our context, the node is selecting from its own wallet on behalf of the EHR. The matching
is deterministic: if a credential matches the query, it is selected. If no credential matches,
an empty result is returned. The caller (e.g., the `CredentialSelector` in the PD matcher) is
responsible for deciding whether an empty result is an error. There is no privacy negotiation
involved.

## Supported subset

### Credential Query (section 6.1)

| Field | Status | Notes |
|-------|--------|-------|
| `id` | Supported | Validated: non-empty, alphanumeric/underscore/hyphen |
| `claims` | Supported | Array of claims queries |
| `format` | Not supported | Format selection handled by Presentation Definition matching |
| `meta` | Not supported | Metadata constraints handled by Presentation Definition matching |
| `multiple` | Not supported | Handled by `match_policy` in the filter chain |
| `claim_sets` | Not supported | Not needed for value-based selection |
| `trusted_authorities` | Not supported | Trust handled by PD matching and DID resolution |
| `require_cryptographic_holder_binding` | Not supported | Handled by VP verification |

### Claims Query (section 6.3)

| Field | Status | Notes |
|-------|--------|-------|
| `path` | Supported | Claims Path Pointer per section 7 |
| `values` | Supported | Exact value matching with OR semantics |
| `id` | Not supported | Only needed with `claim_sets` |

### Claims Path Pointer (section 7)

| Element type | Status | Notes |
|-------------|--------|-------|
| String | Supported | Key lookup in JSON objects |
| Non-negative integer | Supported | Array index lookup |
| Null | Supported | Wildcard — selects all array elements |

The path starts at the credential root, supporting top-level fields (`issuer`, `type`, etc.)
as well as nested `credentialSubject` fields.

`credentialSubject` is unwrapped from its Go array representation (`[]map[string]any`) to a
single object. This allows paths like `["credentialSubject", "patientId"]` instead of
`["credentialSubject", 0, "patientId"]`, since in practice `credentialSubject` always contains
exactly one entry.

## Examples

### Select a PatientEnrollmentCredential by BSN

```json
{
  "id": "id_patient_enrollment",
  "claims": [
    {
      "path": ["credentialSubject", "hasEnrollment", "patient", "identifier", "value"],
      "values": ["123456789"]
    }
  ]
}
```

### Select a credential by multiple possible values (OR)

```json
{
  "id": "id_patient_enrollment",
  "claims": [
    {
      "path": ["credentialSubject", "hasEnrollment", "patient", "identifier", "value"],
      "values": ["123456789", "987654321"]
    }
  ]
}
```

### Select by issuer DID

```json
{
  "id": "id_provider",
  "claims": [
    {
      "path": ["issuer"],
      "values": ["did:x509:0:sha256:abc123::san:otherName:12345678"]
    }
  ]
}
```

### Match a value anywhere in an array (null wildcard)

```json
{
  "id": "id_delegation",
  "claims": [
    {
      "path": ["credentialSubject", "qualifications", null, "roleCode"],
      "values": ["30.000"]
    }
  ]
}
```

This matches if any element in the `qualifications` array has `roleCode` equal to `"30.000"`.

### Multiple claims (AND semantics)

```json
{
  "id": "id_enrollment",
  "claims": [
    {
      "path": ["credentialSubject", "hasEnrollment", "patient", "identifier", "value"],
      "values": ["123456789"]
    },
    {
      "path": ["credentialSubject", "hasEnrollment", "enrolledBy", "identifier", "value"],
      "values": ["87654321"]
    }
  ]
}
```

Both claims must match for a credential to be selected.

## Performance

Benchmark on Apple M5, worst case (match last of 2000 credentials, 2 claims with wildcards,
each credential has multiple identifiers and qualifications):

```
BenchmarkMatch_2000Credentials    ~24ms/op    ~24MB/op    ~504k allocs/op
```

The cost is dominated by `json.Marshal`/`json.Unmarshal` per credential for generic root-level
path resolution. For typical use cases (tens of credentials, not thousands) this is negligible.
