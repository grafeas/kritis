This sample code demonstrates how to use Kritis with Google Cloud Platform's
Container Analysis feature.

The setup.sh script will:
- Configure your project with all necessary APIs
- Configure Cloud Build service account with necessary permissions
- Build a custom Kritis vulnerability policy checking builder

Once everything is set up, you can see it work by running:
gcloud builds submit --config=cloudbuild-good.yaml .

And to exercise a negative case run:
gcloud builds submit --config=cloudbuild-bad.yaml

To set up this demo:
- click the link below to clone this repo in Cloud Shell
- cd samples/policy-check
- gcloud config set project YOURPROJECTNAME
- ./setup.sh

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://ssh.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2Fgrafeas%2Fkritis.git)
