.. _running-docker:

Running on Docker
#################

This guide helps you to configure the Nuts node in Docker.
To use the most recent release use ``nutsfoundation/nuts-node:latest``. For production environments it's advised to use a specific version.

Published images are signed. See :ref:`verifying-images` below to check that an image was built from the published source code.

Examples
********

Docker ``run``
^^^^^^^^^^^^^^

If you want to run without Docker Compose you can use the following command from the working directory:

.. code-block:: shell

  docker run --name nuts -p 8080:8080 -p 8081:8081 \
    -e NUTS_STRICTMODE=false -e NUTS_HTTP_INTERNAL_ADDRESS=":8081" -e NUTS_URL="http://nuts" \
    nutsfoundation/nuts-node:latest


Docker Compose
^^^^^^^^^^^^^^

Copy the following YAML file and save it as ``docker-compose.yaml`` in the working directory.

.. code-block:: yaml

  services:
    nuts:
      image: nutsfoundation/nuts-node:latest
      environment:
        NUTS_STRICTMODE: false
        NUTS_URL: http://nuts
        NUTS_HTTP_INTERNAL_ADDRESS: :8081
      ports:
        - 8080:8080
        - 8081:8081

Start the service:

.. code-block:: shell

  docker compose up

.. note::

    If your use case makes use of ``did:nuts`` DIDs, you also need to export port ``5555``, which is used for gRPC traffic by the Nuts network,
    and add a volume mount for data on ``/nuts/data`` (see below).

You can test whether your Nuts Node is running properly by visiting ``http://localhost:8081/health``. It should
display health information about the state of the node.

User
****

The default user in the container is ``18081`` that is only part of group ``18081``.
This is a regular user without root privileges to provide an additional level of security.
If ``datadir`` config value points to a mounted directory, see the section below how to manage privileges needed by the nuts-node.

Volume mounts
*************

The default working directory within the container is ``/nuts`` that provides defaults for the various configurable data and config paths used:

* **/nuts/config/**: Contains all configuration files.
    Any file changes will take effect *after* a node restart. It is recommended to set read-only privileges (default) to this directory and its contents for additional security.
    (``chmod -R o+r </path/to/host/config-dir>`` assuming the directory on the host is *not* owned by user and/or group ``18081``)

* **/nuts/data/**: Storage directory for data managed by the nuts-node.
    The container user (``18081``) has insufficient privileges by default to write to mounted directories.
    The required permissions can be granted by making the container user the owner of the ``data`` directory on the host. (``chown -R 18081:18081 </path/to/host/data-dir>``)

.. note::

    - Nodes running the :ref:`recommended deployment <nuts-node-recommended-deployment>` (external storage configured for ``crypto.storage`` and ``storage.sql.connection``) that do not use did:nuts / gRPC network don't need to mount a ``data`` dir.

    - *"User 18081 already exists on my host."* See `docker security <https://docs.docker.com/engine/security/userns-remap/>`_ (or relevant container orchestration platform) documentation how to restrict privileges to a user namespace / create a user mapping between host and container.

.. _verifying-images:

Verifying image signatures
**************************


Docker images of the Nuts node are built and pushed to Docker Hub by a GitHub Actions workflow.
The workflow signs each pushed image with `Sigstore <https://www.sigstore.dev/>`_ cosign, using the identity of the workflow itself.
A valid signature proves that the image was built by the CI pipeline of the ``nuts-foundation/nuts-node`` repository, from a specific commit.
An image built on a developer machine and pushed with Docker Hub credentials does not carry a valid signature.

This section shows how to check a signature by hand, how to deploy a verified digest, and how to enforce verification in Kubernetes and in CI pipelines.

.. note::

    Signing was introduced in 6.2.12 and 5.4.39; images of earlier releases are not signed.
    Security fixes are prepared in the private repository ``nuts-foundation/nuts-node-private`` and may be released before their source code is public.
    Images of such a release are signed with the identity of that repository's workflow; the verification commands below accept both identities.
    The source code of an embargoed release becomes available in the public repository at disclosure.

Checking a signature with cosign
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The pipeline signs with cosign 3.
That version stores a signature as a `Sigstore bundle <https://docs.sigstore.dev/about/bundle/>`_, attached to the image through the OCI referrers API, instead of the ``sha256-<digest>.sig`` tag that cosign 2 used.
cosign 2 does not find such a signature and fails with ``no signatures found``, and so does any other verifier that only reads the tag.
The Kubernetes and Azure sections below show which setting switches those verifiers to the bundle format.

Install `cosign <https://docs.sigstore.dev/cosign/system_config/installation/>`_ (version 3.0 or later) and verify a tag:

.. code-block:: shell

  cosign verify nutsfoundation/nuts-node:latest \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp \
      '^https://github.com/nuts-foundation/nuts-node(-private)?/\.github/workflows/build-images\.yaml@'

cosign exits with code 0 and prints the verified claims when the signature is valid.
The two flags pin the identity you trust:

* ``--certificate-oidc-issuer``: the identity provider. For images built on GitHub Actions this is always ``https://token.actions.githubusercontent.com``.
* ``--certificate-identity-regexp``: the workflow that requested the signing certificate. Only the ``build-images.yaml`` workflow in the ``nuts-foundation/nuts-node`` repository, or in ``nuts-foundation/nuts-node-private`` for embargoed security releases, matches this expression.

Each signature is also recorded in the public `Rekor <https://docs.sigstore.dev/rekor/overview>`_ transparency log, so anyone can audit when and by which workflow signatures were produced.

Deploying a verified digest
^^^^^^^^^^^^^^^^^^^^^^^^^^^

A tag such as ``latest`` or a version number is mutable: verifying a tag and pulling the same tag later can yield different images.
To close that gap, deploy by digest.
cosign prints the digest of the image it verified (this command requires ``jq``):

.. code-block:: shell

  DIGEST=$(cosign verify nutsfoundation/nuts-node:latest \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github.com/nuts-foundation/nuts-node(-private)?/\.github/workflows/build-images\.yaml@' \
    --output json | jq -r '.[0].critical.image."docker-manifest-digest"')
  echo "nutsfoundation/nuts-node@${DIGEST}"

Use the printed reference in ``docker run`` or in ``docker-compose.yaml``:

.. code-block:: yaml

  services:
    nuts:
      image: nutsfoundation/nuts-node@sha256:...

Enforcing verification in Kubernetes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The examples in this section and the Azure one below are meant to get you started, not to be pasted into production unchanged.
They are written against the versions named with each example, and setups differ, so try them in your own cluster or pipeline first.
If something turns out to be wrong or outdated, let us know or open a pull request.

An admission controller can reject any pod whose image does not carry a valid signature.
The example below uses `Kyverno <https://kyverno.io/>`_.
The Sigstore `policy-controller <https://docs.sigstore.dev/policy-controller/overview/>`_ offers the same enforcement through a ``ClusterImagePolicy``; set ``signatureFormat: bundle`` on the authority there, for the same reason (policy-controller 0.14 or later).

.. code-block:: yaml

  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata:
    name: verify-nuts-node-images
  spec:
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
            type: SigstoreBundle
            failureAction: Enforce
            attestors:
              - entries:
                  - keyless:
                      issuer: "https://token.actions.githubusercontent.com"
                      subjectRegExp: "^https://github.com/nuts-foundation/nuts-node(-private)?/\\.github/workflows/build-images\\.yaml@"

``type: SigstoreBundle`` is what makes Kyverno read the signature from the OCI referrers API.
Without it Kyverno uses its default type ``Cosign``, which looks for the ``sha256-<digest>.sig`` tag and rejects every Nuts node image.
Both ``type`` and the per-rule ``failureAction`` require Kyverno 1.13 or later.

The policy matches only Nuts node images; other images in the cluster are unaffected.
Kyverno replaces the tag with the verified digest on admission, so the pod runs exactly the image that was verified.
The cluster needs outbound access to Docker Hub for the signature, and to the Sigstore TUF repository (``tuf-repo-cdn.sigstore.dev``) for the trust root.

Azure
^^^^^

* **Azure Kubernetes Service (AKS)**: the Kyverno policy above works unchanged. Azure's own `Image Integrity <https://learn.microsoft.com/en-us/azure/aks/image-integrity>`_ feature (Azure Policy with `Ratify <https://ratify.dev/>`_) is not an alternative for these images: it is a preview feature that its documentation says not to use in production, Notation is its only supported verifier, and Audit is its only supported effect. It cannot check a cosign signature.
* **Azure Container Apps and Container Instances**: these services have no admission control. Verify in the deployment pipeline and deploy by digest.
* **Azure DevOps pipelines**: add a verification step before deployment. The step needs cosign 3.0 or later; pin the version rather than downloading ``latest``.

.. code-block:: yaml

  steps:
    - task: Bash@3
      displayName: Verify nuts-node image signature
      inputs:
        targetType: inline
        script: |
          set -euo pipefail
          COSIGN_VERSION=v3.1.3
          curl -sLo cosign "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
          chmod +x cosign
          DIGEST=$(./cosign verify "nutsfoundation/nuts-node:$(NUTS_VERSION)" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            --certificate-identity-regexp '^https://github.com/nuts-foundation/nuts-node(-private)?/\.github/workflows/build-images\.yaml@' \
            --output json | jq -r '.[0].critical.image."docker-manifest-digest"')
          echo "##vso[task.setvariable variable=NUTS_IMAGE]nutsfoundation/nuts-node@${DIGEST}"

Later pipeline steps deploy ``$(NUTS_IMAGE)``, for example with the ``AzureContainerApps`` or ``KubernetesManifest`` tasks.

Provenance and SBOM
^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^

A valid signature proves that the image was built and pushed by the ``build-images.yaml`` workflow of the ``nuts-foundation/nuts-node`` repository (or ``nuts-node-private`` for embargoed security releases), at the commit recorded in the certificate, and that the image was not modified afterwards.
For an embargoed release the commit is not publicly readable until disclosure; until then the signature proves the origin of the image but the source cannot be audited.
It does not prove that the source code at that commit is free of defects or malicious changes.
Review of the source code, and of who may change it, remains the basis of trust.

Development image
*****************

There's also a development image available which includes an HTTPS tunnel.
This is useful for development and testing purposes. In order to use it, you need a Github account.
The development image is available at Docker hub under ``nutsfoundation/nuts-node:dev``.

You can also build the development image yourself by running the following command in the root of the repository:

.. code-block:: shell

  make docker-dev

When starting up the development image, it'll block and requires you to authenticate with Github.
It'll print a URL to visit in your browser and a code to enter. After authenticating, the tunnel will be established and the Nuts Node will start.
The container stores the last used tunnel in ``/nuts/config/devtunnel/tunnel.id``.
``/nuts/config/devtunnel/tunnel.log`` contains the logs of the tunnel including the public accessible URL. This URL is also printed to the console.
Devtunnel also stores some session information in ``/nuts/DevTunnel``.

To persist a tunnel URL over node restarts, mount a directory at ``/nuts/config/devtunnel`` (or one of its parents) inside the container.
Mounting ``/nuts`` would also persist the current Github session over container restarts.

For trouble shooting devtunnel issues, see the `documentation <https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/>`_ and tunnel usage `limits <https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#dev-tunnels-limits>`_.