# gcp-iam-slackbot
A slackbot controlling GCP Privilege Escalation deployed using cloud functions.

## Deployment
From the root of this repository, run the following two commands.

```
gcloud functions deploy SlashHandler --runtime go113 --trigger-http --allow-unauthenticated --project=gcp-iam-slackbot --set-env-vars SLACK_SECRET=XXXXXXXXX,SLACK_API_TOKEN=XXXXXXXXX,PD_AUTH_TOKEN=XXXXXXXXX --service-account cloud-function-iam-slackbot@gcp-iam-slackbot.iam.gserviceaccount.com

gcloud functions deploy ActionHandler --runtime go113 --trigger-http --allow-unauthenticated --project=gcp-iam-slackbot --set-env-vars SLACK_SECRET=XXXXXXXXX,SLACK_API_TOKEN=XXXXXXXXX,PD_AUTH_TOKEN=XXXXXXXXX --service-account cloud-function-iam-slackbot@gcp-iam-slackbot.iam.gserviceaccount.com
```

This deploys the cloud functions to gcp-iam-slackbot GCP project.


## Local Development
Utilize ngrok to setup a temporary URL you can configure in slack. The URL needs to be put into interactivity and slash commands.
`ngrok http 8080`
`cd cmd/`
`go run main.go`

## Auth
Every request from slack is verified by a signing secret.
For GCP the cloud function will have a service account `cloud-function-iam-slackbot@gcp-iam-slackbot.iam.gserviceaccount.com`, or use ADC for local dev.

# Design Docs

- [Escalation bot design doc](https://docs.google.com/document/d/1PEQtiqhmH0hsrLYkBYq2qSGSMw3Urpoz7hORy02SCWU/edit?skip_itp2_check=true&pli=1#)
- [Hub Admin Access Scopes](https://docs.google.com/document/d/1Oe6N_wAlHSKWlaV6xvqpqimpVGy_MKPu7rbt0j9U7Ug/edit?skip_itp2_check=true&pli=1#)
