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

You'll need credentials that can assume a role with the following policy. Note, you can substitute `*` with the ARN of the repository if you want to limit the role to a specific repository. For multiple specific repos, use add more statement with different ARNs.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability"
            ],
            "Resource": "*"
        }
    ]
}
```


Setup your values.yaml for the helm chart. Specifically include the AWS credentials using the standard AWS SDK environment variables. The easiest way to issue long lived AWS credentials, the most secure way is to use [AWS OIDC](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html) with [Spiffe](https://spiffe.io/). The best reference for AWS SDK environment variables seems to be in the [AWS CLI documentation](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html).  


```yaml
pod:
  container:
    env:
        # How you authenticate to AWS is up to you, see AWS CLI documentation for more options
        - name: AWS_ACCESS_KEY_ID
          value: "EXAMPLE"
        - name: AWS_SECRET_ACCESS_KEY
          value: "EXAMPLE"

        # Recommended that you assume a role with the policy above 
        - name: AWS_ROLE_ARN
          value: "ARN of role with ECR permissions"

        # Important, this must match the region in the image name(s)
        - name: AWS_REGION
          value: "us-east-1" 



```


```sh
helm repo add ecr-anywhere https://centml.github.io/ecr-anywhere
helm repo update
helm install ecr-anywhere ecr-anywhere/ecr-anywhere -f values.yaml
```

Once deployed, you can test it by creating a namespace with the label `ecr-anywhere.centml.ai/namespace: "enabled"`, then a secret of type `kubernetes.io/dockerconfigjson` with the label `ecr-anywhere.centml.ai/managed: "true"`. It doesn't matter what the secret contains, the mutating webhook will overwrite it with fresh ECR credentials. 

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: test
  labels:
    ecr-anywhere.centml.ai/namespace: "enabled"
---
apiVersion: v1
kind: Secret
metadata:
  name: ecr-secret
  namespace: test
  labels:
    ecr-anywhere.centml.ai/managed: "true"
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: "FAKE"
---
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: test
  labels:
    app: test
spec:
  containers:
  - name: test-container
    image: 544849402588.dkr.ecr.us-east-1.amazonaws.com/test:923442bcd004d94c1f7447e1ae14f36d39d77b0e
  imagePullSecrets:
  - name: ecr-secret
```yaml
