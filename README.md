# gcp-iam-slackbot
A slackbot controlling GCP Privlidge Escalation deployed using cloud functions.

## Deployment
From the root of this repository, run the following two commands.
`gcloud functions deploy ActionHandler --runtime go113 --trigger-http --allow-unauthenticated --project=gcp-iam-slackbot --set-env-vars SLACK_SECRET=XXXXXXXXX`
`gcloud functions deploy ActionHandler --runtime go113 --trigger-http --allow-unauthenticated --project=gcp-iam-slackbot --set-env-vars SLACK_SECRET=XXXXXXXXX`


## Local Development
Utilize ngrok to setup a temporary URL you can configure in slack. The URL needs to be put into interactivity and slash commands.
`ngrok http 8080`
`cd cmd/`
`go run main.go`

## Auth
Every request from slack is verified by a signing secret.
For GCP the cloud function will have a service account, or use ADC for local dev. 
