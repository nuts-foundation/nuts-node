# Bug Fix: "credential subjects have no ID" Error with Dezi Credentials

## Problem

Users reported getting this error when calling `RequestServiceAccessToken` with a Dezi credential (id_token):

```json
{
  "detail": "invalid_request - unable to get subject DID from VC: credential subjects have no ID",
  "status": 400,
  "title": "RequestServiceAccessToken failed"
}
```

## Root Cause

The issue was in `AutoCorrectSelfAttestedCredential` (`vcr/credential/util.go`).

### Original Logic (BUGGY)
```go
func AutoCorrectSelfAttestedCredential(credential vc.VerifiableCredential, requester did.DID) vc.VerifiableCredential {
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
            return credential  // ← BUG: Early return without setting credentialSubject.id!
        }
    }
    // ... set credentialSubject.id ...
}
```

**Problem**: The function only checked if the proof type was in `DeziIDJWTProofTypes()` (which returns `["DeziIDJWT07", "DeziIDJWT2024"]`). If:
- Dezi updated their spec with a new proof type (e.g., `DeziIDJWT2025`)
- Or there was any other unrecognized proof type
- The function would return early WITHOUT setting `credentialSubject.id`

### Why This Causes the Error

1. Client calls `RequestServiceAccessToken` with Dezi id_token
2. API converts id_token to `DeziUserCredential` (which has no `credentialSubject.id`)
3. API calls `RequestRFC021AccessToken` with the credential
4. `RequestRFC021AccessToken` applies `AutoCorrectSelfAttestedCredential`
5. **BUG**: Function sees unrecognized proof type, returns early without correction
6. Credential is passed to `wallet.BuildSubmission()`
7. BuildSubmission tries to match credentials and build VP
8. At some point, code calls `credential.ResolveSubjectDID()` or `credential.SubjectDID()`
9. **ERROR**: "credential subjects have no ID"

## The Fix

Changed `AutoCorrectSelfAttestedCredential` to check for `DeziUserCredential` **type** instead of only checking proof types:

```go
func AutoCorrectSelfAttestedCredential(credential vc.VerifiableCredential, requester did.DID) vc.VerifiableCredential {
    // Check if this is a DeziUserCredential - these always need correction regardless of proof type
    isDeziCredential := credential.IsType(DeziUserCredentialTypeURI)
    
    if len(credential.Proof) > 0 && !isDeziCredential {
        // Has proof but not a Dezi credential - only correct if it has a known Dezi proof type
        proofs, _ := credential.Proofs()
        requiresCorrection := false
        for _, p := range proofs {
            if slices.Contains(DeziIDJWTProofTypes(), string(p.Type)) {
                requiresCorrection = true
                break
            }
        }
        if !requiresCorrection {
            return credential
        }
    }
    // No proof OR is Dezi credential OR has Dezi proof type -> apply correction
    // ... set credentialSubject.id ...
}
```

**Key Change**: If the credential has `type=DeziUserCredential`, it will ALWAYS be corrected, regardless of the proof type.

## Test Coverage

### New Test: `Test_DeziCredential_UnrecognizedProofType`
Located in `vcr/holder/eoverdracht_test.go`, this test:
1. Creates a mock Dezi credential with proof type `DeziIDJWT2025` (unrecognized)
2. Verifies it has NO `credentialSubject.id` initially
3. Applies `AutoCorrectSelfAttestedCredential`
4. **Verifies the fix**: Now correctly sets `credentialSubject.id` even with unrecognized proof type

### Existing Tests
All existing tests continue to pass:
- ✅ `TestAutoCorrectSelfAttestedCredential` (vcr/credential)
- ✅ `Test_DeziCredential_noSubjectID` (vcr/holder)
- ✅ All holder tests
- ✅ All auth/client/iam tests
- ✅ All auth/api/iam tests

## Impact

This fix ensures that:
1. **Future-proof**: If Dezi updates their proof type, the system will still work
2. **Robust**: The credential **type** (`DeziUserCredential`) is the authoritative indicator, not the proof type
3. **Backward compatible**: Existing Dezi credentials with recognized proof types continue to work
4. **No breaking changes**: All existing tests pass

## Files Modified

1. `/Users/reinkrul/workspace/nuts-node/vcr/credential/util.go` - Fixed `AutoCorrectSelfAttestedCredential`
2. `/Users/reinkrul/workspace/nuts-node/vcr/holder/eoverdracht_test.go` - Added reproducer test
3. `/Users/reinkrul/workspace/nuts-node/auth/client/iam/openid4vp.go` - Enhanced comments

