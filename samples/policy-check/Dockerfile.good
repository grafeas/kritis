# Debian10 image from Jun 8th, 2020
FROM gcr.io/google-appengine/debian10@sha256:d2e40ef81a0f353f1b9c3cf07e384a1f23db3acdaa0eae4c269b653ab45ffadf

# Just so the built image is always unique
RUN apt-get --allow-releaseinfo-change update && apt-get -y install uuid-runtime && uuidgen > /IAMUNIQUE
