#!/bin/bash

set -ev

echo testing std
dub test --config std
dub test --config std --compiler ldc2

echo testing vibed
cat << EOF > dub.selections.json
{
    "fileVersion": 1,
    "versions": {
        "vibe-d": "0.8.3-alpha.1",
        "vibe-core": "1.4.0-alpha.1"
    }
}
EOF
dub test --config vibed
dub test --config vibed --compiler ldc2
rm dub.selections.json

