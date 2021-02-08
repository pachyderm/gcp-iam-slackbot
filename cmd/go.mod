module iambot

go 1.14

replace gcpiamslack => ../../gcp-iam-slackbot

require (
	gcpiamslack v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.7.0
)
