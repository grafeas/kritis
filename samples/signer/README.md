This sample code demonstrates how to use Kritis with Google Cloud Platform's
Binary Authorization feature.

The setup.sh script will:
- Configure your project with all necessary APIs
- Build a custom python based vulnerability analysis polling builder
- Build a custom Kritis vulnerability attestation signing builder
- Set up keys for the vulnerability attestation
- Set up the attestor
- Create a cluster to deploy into

Once everything is set up, you can see it work by running:
gcloud builds submit --config=cloudbuild-good.yaml .

And to exercise a negative case run:
gcloud builds submit --config=cloudbuild-bad.yaml

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://ssh.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2Fdonmccasland%2Fkritis.git&cloudshell_git_branch=signer-cli&cloudshell_working_dir=gopath%2Fsrc%2Fgithub.com%2Fgrafeas%2Fkritis)
