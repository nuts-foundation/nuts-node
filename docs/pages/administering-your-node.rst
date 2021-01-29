.. _administering-your-node:

Adminstering your node
######################

The Nuts executable this project provides can be used to both run a Nuts server (a.k.a. node) and administer a running
node remotely. This chapter explains how to administer your running Nuts node.

Prerequisites
*************

The following is needed to run a Nuts node:

1. Nuts executable for your platform (Docker guide is coming soon).
2. The address of your running Nuts node. You can pass this using the `address` variable.

Commands
********

Run the executable without command or flags, or with the `help` command to find out what commands are supported:

    $ nuts

For example, to list all network documents in your node (replace the value of `NUTS_ADDRESS` with the HTTP address of your Nuts node):

    $ NUTS_ADDRESS=my-node:1323 nuts network list
