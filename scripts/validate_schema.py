# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A command line script used to validating JSON data against a schema."""
import argparse
import json
import logging

import jsonschema
from jsonschema import validate


def validate_json_schema(json_data: dict, schema: dict) -> None:
    """Validates a JSON object against a given schema.

    Args:
        json_data (dict): The JSON data to validate.
        schema (dict): The schema to validate against.

    Raises:
        jsonschema.exceptions.ValidationError: If the JSON data does not conform to the schema.
    """
    try:
        validate(instance=json_data, schema=schema)
        logging.info("JSON data is valid against the schema.")
    except jsonschema.exceptions.ValidationError as err:
        logging.error(f"JSON data is invalid: {err.message}")
        raise

    return True


def main() -> None:
    """Main function to handle command-line arguments and validate JSON data against a schema."""
    logging.basicConfig(level=logging.INFO)

    # Load the JSON data and schema from files
    parser = argparse.ArgumentParser(description="Validate JSON data against a schema.")
    parser.add_argument("json_data", help="Path to the JSON data file.")
    parser.add_argument("schema", help="Path to the schema file.")
    args = parser.parse_args()

    with open(args.json_data, "r") as json_file:
        json_data = json.load(json_file)

    with open(args.schema, "r") as schema_file:
        schema = json.load(schema_file)

    # Validate the JSON data against the schema
    if validate_json_schema(json_data, schema):
        logging.info("JSON data is valid against the schema.")

if __name__ == "__main__":
    main()
