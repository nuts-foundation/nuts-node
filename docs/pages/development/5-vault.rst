 .. _vault-dev:

Development with Vault
######################

You can start a development Vault server as follows:

.. code-block:: shell

    docker run --cap-add=IPC_LOCK -d -p 8200:8200 \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=unsafe' -e 'VAULT_ADDRESS=http://localhost:8200' \
    --name=dev-vault \
    vault

The server will start unsealed, with root token ``unsafe``.

Now log in and enable a key-value secret engine named ``kv``:

.. code-block:: shell

    docker exec -e 'VAULT_ADDR=http://0.0.0.0:8200' dev-vault vault login

Enter the root token ``unsafe``, then enable the ``kv`` engine:

.. code-block:: shell

    docker exec -e 'VAULT_ADDR=http://0.0.0.0:8200' dev-vault vault secrets enable -path=kv kv

Then configure the Nuts node to use the Vault server:

.. code-block:: yaml

    crypto:
      storage: vaultkv
      vault:
        address: http://localhost:8200
        token: unsafe
