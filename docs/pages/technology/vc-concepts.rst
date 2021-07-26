.. _vc-concepts:

VC Concept mapping
##################

Verifiable Credentials are, by nature, very dynamic. This is reflected by the data format: either JSON or fields within a JWT (basically also JSON).
There are two ways to cope with this: 1) transform every credential to a fixed concept. This creates a reliable DB but requires custom code for each credential type.
Or 2) store the credential in a document store and provide a way to interact with the credentials through some interface where magic happens.

We opted for the latter and call it concept mappings. A *concept* represents a selection of data that is needed to support bolts.
An example concept is a care organization. A key part of a care organization is it's name. This name is given to a DID via a Verifiable Credential.
Multiple credentials can give a DID its name, the concept mappings makes sure only a single interface is required at the side of the Nuts node.

See :ref:`preconfigured concepts <default-concepts>` for a list of supported concepts.

Configuration
*************

Credentials are configured to have indices and a template for transformation.

The organization credential configuration looks like this:

.. code-block:: yaml

    concept: organization
    credentialType: NutsOrganizationCredential
    indices:
      - name: index_id
        parts:
          - path: id
      - name: index_issuer
        parts:
          - path: issuer
      - name: index_subject
        parts:
          - path: credentialSubject.id
            alias: subject
      - name: index_name_city
        parts:
          - path: credentialSubject.organization.name
            alias: organization.name
            tokenizer: whitespace
            transformer: cologne
          - path: credentialSubject.organization.city
            alias: organization.city
            tokenizer: whitespace
            transformer: cologne
    template: |
        {
          "id": "<<id>>",
          "issuer": "<<issuer>>",
          "type": "NutsOrganizationCredential",
          "subject": "<<credentialSubject.id>>",
          "organization": {
            "name": "<<credentialSubject.organization.name>>",
            "city": "<<credentialSubject.organization.city>>"
          }
        }

It contains 4 main parts: `concept`, `credentialType`, `indices` and `template`.
The NutsOrganizationCredential is mapped to the `organization` concept.
When searching for credentials, you use the concept name. When creating a credential you use the credential type.
When you resolve a credential, you'll always get the raw credential.

Indices
=======

Each configuration may contain a list of indices. Each index has a name and contains a list of parts.
The name of the index is used to identify the index. Each index is scoped to its own credential type.
An index part must contain a `path`. The path is a JSON path query.
The values found at that location will be used for indexing.
See [go-leia](https://github.com/nuts-foundation/go-leia) for the syntax and available options.

An index part may contain an `alias`. The alias is used as a search key.
In the example above, the JSON path `credentialSubject.organization.name` has an alias of `organization.name`.
This means that in a search query the key `organization.name` can be used.
Aliases are not unique to a credential type. This allows for searching over multiple credential types with a single query.

An index part can also contain a transformer and/or a tokenizer. A tokenizer will split a value into multiple values to be indexed.
For example: the whitespace tokenizer will split a sentence into a list of words to be indexed.
The name *healthcare organization the Nutty professor* will be split and can be found by just searching for *healthcare*, *organization*, *the*, *Nutty* or *professor*.
Possible values for tokenizer: `whitespace`.

A transformer transforms a value before the value is used as an index key. A transformer will also transform search parameters that use that index.
For example: the lowercase transformer will transform all indexed values and search params to lowercase.
The word *Nutty* in the previous example could then be found with *nutty*, *NUTTY* or any other combination of upper- and lowercase letters.
Possible values for transformer: `lowerCase`, `cologne`.

The `cologne` transformer is a phonetic transformer. It's like soundex but works better for germanic type languages.

Template
========

The template is used to transform a credential to a common output format when searching for a concept.
Values that start with `<<` and end with `>>` are JSON path expressions.
They are replaced with the result of the JSON path expression when applied to found credentials.
A template is optional. When not defined, the raw credential is returned.

Using arrays is currently not supported in a template.
