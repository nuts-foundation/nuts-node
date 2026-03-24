# Dezi Credential Handling and credentialSubject.id

## Overview

Dezi credentials (DeziUserCredential) are special credentials that don't inherently have a `credentialSubject.id` field when created. This is because they represent user attestations from an external system (Dezi) and are not initially tied to a specific wallet DID.

## The Problem

When credentials are used in presentation submissions, the system needs to determine:
1. Which DID should sign the presentation
2. Which credentials belong to which wallet DID

For normal credentials, this is straightforward - they have a `credentialSubject.id` that identifies the subject. However, Dezi credentials don't have this field initially, which would cause errors when trying to build presentations.

## The Solution: API Layer Processing

The API layer applies `credential.AutoCorrectSelfAttestedCredential()` to set the `credentialSubject.id` field for Dezi credentials (and other self-attested credentials) when they are provided as "additional credentials" to the access token request.

### Where This Happens

In `/auth/client/iam/openid4vp.go`, the `RequestRFC021AccessToken` method:

```go
// each additional credential can be used by each DID
additionalWalletCredentials := map[did.DID][]vc.VerifiableCredential{}
for _, subjectDID := range subjectDIDs {
    for _, curr := range additionalCredentials {
        additionalWalletCredentials[subjectDID] = append(
            additionalWalletCredentials[subjectDID], 
            credential.AutoCorrectSelfAttestedCredential(curr, subjectDID)
        )
    }
}
```

### What AutoCorrectSelfAttestedCredential Does

The function (in `/vcr/credential/util.go`) performs the following for Dezi credentials:
1. Checks if the credential has a Dezi proof type (`DeziIDJWT07` or `DeziIDJWT2024`)
2. Sets `credentialSubject.id` to the wallet DID if not already set
3. Sets other required fields like `issuer`, `issuanceDate`, and `id` if missing

### Why Each Wallet DID Gets a Copy

The code creates a copy of each Dezi credential for each wallet DID managed by the tenant/subject. This is because:
- A tenant can have multiple wallet DIDs (e.g., did:web, did:nuts)
- The Dezi credential needs to be associated with each wallet DID
- The presentation building logic needs to know which credentials belong to which DID

## Testing

The tests in `eoverdracht_test.go` demonstrate this behavior:

1. **Test_DeziCredential_noSubjectID**: Shows that a raw Dezi credential has no `credentialSubject.id`, and after applying `AutoCorrectSelfAttestedCredential`, the field is properly set.

2. **Test_eOverdracht_reproduceIssue**: Demonstrates the full flow with multiple credentials, showing that:
   - Without `AutoCorrectSelfAttestedCredential`: Dezi credentials lack `credentialSubject.id`
   - With `AutoCorrectSelfAttestedCredential`: All credentials have the field properly set

## Key Takeaways

1. **Dezi credentials are provided as "additional credentials"** in the API request
2. **The API layer is responsible for setting `credentialSubject.id`** by calling `AutoCorrectSelfAttestedCredential`
3. **Each wallet DID gets its own copy** of the Dezi credential with `credentialSubject.id` set to that DID
4. **This is NOT done in the wallet/holder layer** - it's API layer preprocessing before calling `BuildSubmission`
5. **The function only modifies unsigned JSON-LD credentials and credentials with Dezi proof types** - it won't modify signed JWT credentials

