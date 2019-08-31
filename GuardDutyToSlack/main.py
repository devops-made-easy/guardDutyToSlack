import json
import os
import requests


def get_severity_level(severity):
    if severity == 0.0:
        level = {'label': 'INFO', 'color': 'good'}
    elif 0.1 <= severity <= 3.9:
        level = {'label': 'LOW', 'color': 'warning'}
    elif 4.0 <= severity <= 6.9:
        level = {'label': 'MEDIUM', 'color': 'warning'}
    elif 7.0 <= severity <= 8.9:
        level = {'label': 'HIGH', 'color': 'danger'}
    elif 9.0 <= severity <= 10.0:
        level = {'label': 'CRITICAL', 'color': 'danger'}
    else:
        level = {'label': 'UN_KNOWN', 'color': 'danger'}
    return level


def lambda_handler(event, context):
    # print the event recieved from cloud watch event rule
    print(json.dumps(event))

    # Read the environment varaibles of lambda
    webhook = os.environ['SLACK_WEBHOOK_URL']
    sev_level = os.environ['SEVERITY_LEVEL']

    # assign the varaible with valid values from event recieved.
    consoleUrl = "https://console.aws.amazon.com/guardduty"
    finding = event['detail']['type']
    findingDescription = event['detail']['description']
    findingTime = event['detail']['updatedAt']
    account = event['detail']['accountId']
    region = event['detail']['region']
    eventId = event['detail']['id']

    # get the severity level of the guard duty finding.
    severity_level = get_severity_level(event['detail']['severity'])

    # generate a payload that will be sent to slack api
    payload = {
        'username': 'GuardDuty Finding',
        'icon_url': 'https://raw.githubusercontent.com/aws-samples/amazon-guardduty-to-slack/master/images/gd_logo.png',
        'attachments': [
            {
                'fallback': f"{finding} {consoleUrl}/home?region={region}#/findings?macros=current&fId={eventId}",
                'color': severity_level['color'],
                'title': finding,
                'title_link': f"{consoleUrl}/home?region={region}#/findings?macros=current&fId={eventId}",
                'text': findingDescription,
                'fields': [
                    {
                        'title': 'Account ID',
                        'value': event['detail']['accountId'],
                        'short': True
                    },
                    {
                        'title': 'Severity',
                        'value': severity_level['label'],
                        'short': True
                    },
                    {
                        'title': 'Region',
                        'value': region,
                        'short': True
                    },
                    {
                        'title': 'Last Seen',
                        'value': findingTime,
                        'short': True
                    },
                    {
                        'title': 'Type',
                        'value': event['detail']['type'],
                        'short': False
                    },
                ]
            }
        ]
    }

    # Post an update to slack.
    print(float(event['detail']['severity']))
    print(float(sev_level))
    if float(event['detail']['severity']) >= float(sev_level):
        slack_response = requests.post(webhook, json.dumps(payload), headers={
            'content-type': 'application/json'})
    else:
        slack_response = "Not eligible to Send"

    # print(os.environ['SLACK_WEBHOOK_URL'])
    print(slack_response)
    return {
        "statusCode": 200,
        "body": {
            "message": str(slack_response),
            # "location": ip.text.replace("\n", "")
        },
    }
