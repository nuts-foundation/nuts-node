# Analysis: "credential subjects have no ID" Error in BuildSubmission

## Error Message
```
{
  "detail": "invalid_request - unable to get subject DID from VC: credential subjects have no ID",
  "status": 400,
  "title": "RequestServiceAccessToken failed"
}
```

## Code Path

### 1. Client API Entry Point
`auth/api/iam/api.go:728` - `RequestServiceAccessToken()`
- Line 759: Creates Dezi credential from id_token
- Line 803: Calls `RequestRFC021AccessToken` with credentials including Dezi

### 2. Client IAM Module
`auth/client/iam/openid4vp.go:246` - `RequestRFC021AccessToken()`
- Line 325: Applies `AutoCorrectSelfAttestedCredential` to each additional credential for each wallet DID
- Line 328: Calls `wallet.BuildSubmission()` with corrected credentials

### 3. Holder Module
`vcr/holder/presenter.go:52` - `buildSubmission()`
- Line 77: Calls `builder.Build(format)` to match credentials
- Line 84: Calls `buildPresentation()` with matched credentials

`vcr/holder/presenter.go:100` - `buildPresentation()`
- Line 102-106: **IF signerDID is nil**, calls `credential.ResolveSubjectDID(credentials...)`
  - This calls `SubjectDID()` on each credential
  - **THIS IS WHERE THE ERROR OCCURS** if any credential lacks `credentialSubject.id`

## Root Cause Analysis

The error can only occur if `AutoCorrectSelfAttestedCredential` FAILS to set `credentialSubject.id`. This happens when:

### Condition 1: Proof Check Fails (lines 124-136 of util.go)
```go
if len(credential.Proof) > 0 {
    proofs, _ := credential.Proofs()
    requiresCorrection := false
    for _, p := range proofs {
        if slices.Contains(DeziIDJWTProofTypes(), string(p.Type)) {
            requiresCorrection = true
            break
        }
    }
    if !requiresCorrection {
        return credential  // ← EARLY RETURN WITHOUT CORRECTION!
    }
}
```

**Issue**: If a Dezi credential has a proof BUT the proof type is NOT recognized as a Dezi proof type, it returns early without setting `credentialSubject.id`.

### Condition 2: Multiple or Zero Credential Subjects (lines 147-154 of util.go)
```go
if len(credentialSubject) == 1 {
    // ... set credentialSubject[0]["id"]
}
// ← If len != 1, nothing is set!
```

**Issue**: If credentialSubject is empty or has multiple entries, the ID is not set.

## Potential Scenarios

### Scenario A: Proof Type Mismatch
1. Dezi updates their spec and changes the proof type
2. `CreateDeziUserCredential` creates a credential with the new proof type
3. `DeziIDJWTProofTypes()` doesn't include the new type yet
4. `AutoCorrectSelfAttestedCredential` sees a proof but doesn't recognize it as Dezi
5. Returns early without setting `credentialSubject.id`
6. `buildPresentation` calls `ResolveSubjectDID` which fails

### Scenario B: Credential Subject Structure Issue
1. `CreateDeziUserCredential` creates the credential
2. The `credentialSubject` field is somehow not exactly length 1 (could be 0 or >1)
3. `AutoCorrectSelfAttestedCredential` skips setting the ID
4. `buildPresentation` fails

### Scenario C: signerDID is nil
1. `buildPresentation` is called with `signerDID = nil`
2. This triggers the `ResolveSubjectDID` call on line 102
3. If ANY credential in the set doesn't have `credentialSubject.id`, it fails
4. But looking at line 84 of presenter.go, `signInstruction.Holder` is always passed
5. **This scenario seems unlikely in the normal flow**

## Most Likely Root Cause

**Scenario A (Proof Type Mismatch)** is the most likely cause:
- The proof type check in `AutoCorrectSelfAttestedCredential` is too strict
- It only corrects if there's NO proof OR if the proof is a recognized Dezi type
- If Dezi adds a new proof type or there's a version mismatch, the credential won't be corrected

## Solution

The `AutoCorrectSelfAttestedCredential` function should be more lenient. Instead of checking for specific Dezi proof types, it should:
1. Check if the credential is a `DeziUserCredential` type
2. If yes, apply the correction regardless of proof type

Or alternatively, make the function always set `credentialSubject.id` if it's missing, regardless of proof type (for any credential passed as "additional").

