#!/bin/bash
GPG_OUTPUT="$(gpg --quick-generate-key --yes attestor@example.com)"
KEY_FINGERPRINT="$(echo $GPG_OUTPUT | sed -n 's/.*\([A-Z0-9]\{40\}\).*/\1/p')"
gpg --armor --export $KEY_FINGERPRINT > gpg.pub
gpg --armor --export-secret-keys $KEY_FINGERPRINT > gpg.priv

