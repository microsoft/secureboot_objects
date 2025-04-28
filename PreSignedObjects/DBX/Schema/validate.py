
import json

import jsonschema
from jsonschema import RefResolver

with open("dbx_revocation_schema.json", "r") as f:
    dbx_revocation_schema = json.load(f)

with open("SecureBootDataTypes/svn_schema.json", "r") as f:
    svn_schema = json.load(f)

with open("SecureBootDataTypes/hash_schema.json", "r") as f:
    hash_schema = json.load(f)

# Example JSON data based on the provided schema
with open("example.json", "r") as f:
    example_data = json.load(f)
    print(example_data)

# Validate the example data against the DBX Revocation Schema



# Create a resolver to handle references within the schemas
resolver = RefResolver(
    base_uri='',
    referrer=dbx_revocation_schema,
    store={
    'svn_schema.json': svn_schema,
    'hash_schema.json': hash_schema,
    'cert_schema.json': dbx_revocation_schema,
    }
)


# Validate the example data against the DBX Revocation Schema
#try:
jsonschema.validate(instance=example_data, schema=dbx_revocation_schema, resolver=resolver)
print("Example data is valid according to the DBX Revocation Schema.")
#except jsonschema.exceptions.ValidationError as e:
#    print(f"Example data is invalid according to the DBX Revocation Schema: {e.message}")
