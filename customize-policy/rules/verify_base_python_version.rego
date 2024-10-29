#
# METADATA
# title: Verify Base Python image version
# description: >-
#   This package is responsible for verifying the version of base Python image to be 1-117.1684741281
#
package verify_base_python_version

import rego.v1

import data.lib

# METADATA
# title: Verify Python image version to match 1-117.1684741281
# description: Confirm that the version of base base image used in the
#   Dockerfile of project is equal to 1-117.1684741281
# custom:
#   short_name: verify_base_python_version
#   failure_msg: Python base image's version isn't 1-117.1684741281
#   solution: Update the version of Python image in Dockerfile to 1-117.1684741281
deny contains result if {
    required_version := "1-117.1684741281"
    not (required_version in python_version)

    result := lib.result_helper(rego.metadata.chain(), [])
}

# Rule to extract the Go version from the environment variables
python_version contains ver if {
    some env in input.image.config.Env
    startswith(env, "PYTHON_VERSION=")
    split(env, "=", parts)
    ver = parts[1]
}
