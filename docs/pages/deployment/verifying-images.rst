.. _verifying-images:

Verifying image signatures
##########################

Docker images of the Nuts node are built and pushed to Docker Hub by a GitHub Actions workflow.
The workflow signs each pushed image with `Sigstore <https://www.sigstore.dev/>`_ cosign, using the identity of the workflow itself.
A valid signature proves that the image was built by the CI pipeline of the ``nuts-foundation/nuts-node`` repository, from a specific commit.
An image built on a developer machine and pushed with Docker Hub credentials does not carry a valid signature.

This page shows how to check a signature by hand, how to deploy a verified digest, and how to enforce verification in Kubernetes and in CI pipelines.

.. note::

    Images published before signing was added to the release pipeline are not signed.
    Security fixes may be released before their source code is public.
    Such an image can fail strict verification until the source is published; the release notes state this when it applies.

Checking a signature with cosign
********************************

Install `cosign <https://docs.sigstore.dev/cosign/system_config/installation/>`_ (version 2 or later) and verify a tag:

.. code-block:: shell

  cosign verify nutsfoundation/nuts-node:latest \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp \
      '^https://github.com/nuts-foundation/nuts-node/\.github/workflows/build-images\.yaml@'

cosign exits with code 0 and prints the verified claims when the signature is valid.
The two flags pin the identity you trust:

* ``--certificate-oidc-issuer``: the identity provider. For images built on GitHub Actions this is always ``https://token.actions.githubusercontent.com``.
* ``--certificate-identity-regexp``: the workflow that requested the signing certificate. Only the ``build-images.yaml`` workflow in the ``nuts-foundation/nuts-node`` repository matches this expression.

Each signature is also recorded in the public `Rekor <https://docs.sigstore.dev/rekor/overview>`_ transparency log, so anyone can audit when and by which workflow signatures were produced.

Deploying a verified digest
***************************

A tag such as ``latest`` or a version number is mutable: verifying a tag and pulling the same tag later can yield different images.
To close that gap, deploy by digest.
cosign prints the digest of the image it verified (this command requires ``jq``):

.. code-block:: shell

  DIGEST=$(cosign verify nutsfoundation/nuts-node:latest \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github.com/nuts-foundation/nuts-node/\.github/workflows/build-images\.yaml@' \
    --output json | jq -r '.[0].critical.image."docker-manifest-digest"')
  echo "nutsfoundation/nuts-node@${DIGEST}"

Use the printed reference in ``docker run`` or in ``docker-compose.yaml``:

.. code-block:: yaml

  services:
    nuts:
      image: nutsfoundation/nuts-node@sha256:...

Enforcing verification in Kubernetes
************************************

An admission controller can reject any pod whose image does not carry a valid signature.
The example below uses `Kyverno <https://kyverno.io/>`_.
The Sigstore `policy-controller <https://docs.sigstore.dev/policy-controller/overview/>`_ offers the same enforcement through a ``ClusterImagePolicy``.

.. code-block:: yaml

  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata:
    name: verify-nuts-node-images
  spec:
    validationFailureAction: Enforce
    webhookTimeoutSeconds: 30
    rules:
      - name: require-signed-nuts-node
        match:
          any:
            - resources:
                kinds:
                  - Pod
        verifyImages:
          - imageReferences:
              - "docker.io/nutsfoundation/nuts-node*"
            attestors:
              - entries:
                  - keyless:
                      issuer: "https://token.actions.githubusercontent.com"
                      subjectRegExp: "^https://github.com/nuts-foundation/nuts-node/\\.github/workflows/build-images\\.yaml@"
                      rekor:
                        url: "https://rekor.sigstore.dev"

The policy matches only Nuts node images; other images in the cluster are unaffected.
Kyverno replaces the tag with the verified digest on admission, so the pod runs exactly the image that was verified.
The cluster needs outbound access to Docker Hub to fetch signatures.

Azure
*****

* **Azure Kubernetes Service (AKS)**: the Kyverno policy above works unchanged. Azure also offers a built-in image integrity feature based on Azure Policy and `Ratify <https://ratify.dev/>`_; see the `AKS image integrity documentation <https://learn.microsoft.com/en-us/azure/aks/image-integrity>`_ for the signature formats it currently supports.
* **Azure Container Apps and Container Instances**: these services have no admission control. Verify in the deployment pipeline and deploy by digest.
* **Azure DevOps pipelines**: add a verification step before deployment. Pin the cosign version in real pipelines instead of downloading ``latest``.

.. code-block:: yaml

  steps:
    - task: Bash@3
      displayName: Verify nuts-node image signature
      inputs:
        targetType: inline
        script: |
          set -euo pipefail
          curl -sLo cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
          chmod +x cosign
          DIGEST=$(./cosign verify "nutsfoundation/nuts-node:$(NUTS_VERSION)" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            --certificate-identity-regexp '^https://github.com/nuts-foundation/nuts-node/\.github/workflows/build-images\.yaml@' \
            --output json | jq -r '.[0].critical.image."docker-manifest-digest"')
          echo "##vso[task.setvariable variable=NUTS_IMAGE]nutsfoundation/nuts-node@${DIGEST}"

Later pipeline steps deploy ``$(NUTS_IMAGE)``, for example with the ``AzureContainerApps`` or ``KubernetesManifest`` tasks.

Provenance and SBOM
*******************

Each image contains SLSA build provenance and an SPDX software bill of materials, embedded as attestation manifests in the image index.
The provenance records the source repository, the commit, and the build parameters.
Inspect them with:

.. code-block:: shell

  docker buildx imagetools inspect nutsfoundation/nuts-node:latest \
    --format '{{ json .Provenance }}'
  docker buildx imagetools inspect nutsfoundation/nuts-node:latest \
    --format '{{ json .SBOM }}'

The attestations are part of the image index, so the cosign signature on the image digest covers them.

Scope of the guarantee
**********************

A valid signature proves that the image was built and pushed by the ``build-images.yaml`` workflow of the ``nuts-foundation/nuts-node`` repository, at the commit recorded in the certificate, and that the image was not modified afterwards.
It does not prove that the source code at that commit is free of defects or malicious changes.
Review of the source code, and of who may change it, remains the basis of trust.
