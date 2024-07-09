# ECR Anywhere

## Description
ECR Anywhere makes it easy to use container images hosted in private ECR repositories on any Kubernetes cluster, especially those hosted outside of AWS. It works via two components: 

  1) A Mutating Webhook that intercepts create/update verbs on labeled Kubernetes Secrets, injecting fresh ECR credentials which expire in 12 hours.
  2) A CronJob that periodically checks the specially labeled Kubernetes Secrets to see if they need to be refreshed. If they do, an annotation is updated, synchronously triggering a credential refresh by the Mutating Webhook.

The benefits of this approach are the simplicity in implementation and operations (monitoring/alerting). 

From an operational perspective: 

  1) A properly labeled secret can not be created or updated unless ecr-anywhere is working as expected. There's immediate feedback during operational setup/maintenance.  
  2) Any automation issues refreshing credentials are known immediately to operators with basic alerting on CronJob failures/pod failures. 


## Quick Start

Setup your values.yaml for the helm chart. Specifically include the AWS credentials using the standard AWS SDK environment variables. The easiest way to issue long lived AWS credentials, the most secure way is to use [AWS OIDC](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html) with [Spiffe](https://spiffe.io/). The best reference for AWS SDK environment variables seems to be in the [AWS CLI documentation](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html).  

```yaml

pod:
  container:
    env:
        - name: AWS_ACCESS_KEY_ID
          value: "EXAMPLE"
        - name: AWS_SECRET_ACCESS_KEY
          value: "EXAMPLE"
        - name: AWS_REGION
          #important, this must match the region in the image name
          value: "us-east-1" 
```


```sh
helm install ecr-anywhere ./charts/ecr-anywhere -f values.yaml
```

