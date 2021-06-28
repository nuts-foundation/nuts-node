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

Templates
*********

Credentials are mapped on a concept through templates.

An example concept mapping template looks like this:

.. code-block:: json

    {
        "id": "<<id>>",
        "issuer": "<<issuer>>",
        "type": "ExampleCredential",
        "credentialSubject": {
            "id": "<<subject>>@B{2}",
            "organization": {
                "name": "<<organization.name>>@T{1}",
                "city": "<<organization.city>>"
            }
        }
    }

it follows the syntax of a Verifiable Credential. Only the parts of the credential that are mapped (and type) are in the template.
The example template above introduces the `organization` concept. That name must also be used in the APIs.
A concept is automatically derived from any *conceptValue* with a `.` in it. Any field that is encapsulated between `<<` and `>>` is called a *conceptValue*.
This *conceptValue* is also used in the APIs and CLI. It can be used as JSON like:

.. code-block:: json

    {
        "organization": {
            "name": "X",
            "city": "Y"
        }
    }

or as key-value:

.. code-block:: bash

    organization.name=X
    organization.city=Y

Generic fields
==============

The following template only defines the generic fields. The generic fields are required for each credential. A `type` is also always required.

.. code-block:: json

    {
        "id": "<<id>>",
        "issuer": "<<issuer>>",
        "type": "SomeCredential",
        "credentialSubject": {
            "id": "<<subject>>",
        }
    }

Indices
=======

When searching for or manipulating records in a DB, it's always important to have the correct indices.
It doesn't really matter which DB you're using, it'll always require some sort of index to be able to perform.

In the concept templates, we use the `@T{1_1},{2_1}` syntax for this. The full regex is:

.. code-block:: text

    ((<<[a-zA-Z\.]+>>)|([a-zA-Z\.]+))(@([T|B]{[1-9](_[1-9])?})(,[T|B]{[1-9](_[1-9])?})*)?

Every entry between `{` and `}` represents an index. It contains multiple numbers that it represents a compound index.
The second number is the place in the compound index. Every combination of numbers must be unique.
The indices are dependent on the use case. For example: revoking requires an index on `issuer` and `id` (to find all issued and to revoke).
The letter before the `{` determines the type of index: `T` for text and `B` for bytes.
The range index will index the field as an array of bytes. The text index will index the field as a phonetic index.

Restrictions
============

Using arrays is currently not supported in a template.
