#!/bin/bash

# run this script from the root of the Repo.
# This script will extract the client lib files from containeranalysis-go.tar into
# vendor directory.
# Run this script after you run dep ensure.
tar xvf hack/containeranalysis-go.tar -C vendor/ cloud.google.com/
