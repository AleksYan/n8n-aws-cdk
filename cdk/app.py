#!/usr/bin/env python3
import os

import aws_cdk as cdk
from aws_cdk import DefaultStackSynthesizer

from cdk.cdk_stack import N8nStack


app = cdk.App()

# Get region from environment variable - this is now mandatory
region = os.getenv('CDK_DEPLOY_REGION')
if not region:
    raise ValueError("Region must be specified using CDK_DEPLOY_REGION environment variable. Use deploy.sh --region [region] to deploy.")
print(f"Deploying to region: {region}")

# Create a custom synthesizer with our qualifier
synthesizer = DefaultStackSynthesizer(
    qualifier="n8npoc"
)

N8nStack(app, "N8nStack",
    # Use the region from environment variables or default
    env=cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=region),
    synthesizer=synthesizer,
    )

app.synth()
