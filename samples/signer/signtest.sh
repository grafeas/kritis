#!/bin/bash
../../out/signer -v 10 \
-alsologtostderr \
-image=gcr.io/projectgut-215417/debian10@sha256:8eb104d2e735222bc3a9dd3f306575759bc6ee147615bcab36c514c0b8540951 \
-credentials=kritis-service-account.json \
-public_key=gpg.pub \
-private_key=gpg.priv \
-policy=policy.yaml
