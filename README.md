## **Kube Auth**

Kube Auth is a webhook handler service for the kubernetes token and auhorizations webhook modes. The service essentually wraps the code for CSV tokens and ABAC policy and presents them to the kubernetes API as a HTTP endpoint. The service will also handle the reloading of files on changes, i.e a new token added will reload etc.

#### **- Integretion**

This is better documented in the kubernetes docs, but a general gist is you need to create the two webhook files as below and update the kubeapi settings.


```YAML
clusters:
- name: local
  cluster:
    certificate-authority: /etc/ssl/certs/platform_ca.pem
    server: https://127.0.0.1:8443/authorize/token
users:
- name: local
current-context: local
contexts:
- context:
    cluster: local
    user: local
  name: local
```

```YAML
clusters:
- name: local
  cluster:
    certificate-authority: /etc/ssl/certs/platform_ca.pem
    server: https://127.0.0.1:8443/authorize/token
users:
- name: local
current-context: local
contexts:
- context:
    cluster: local
    user: local
  name: local
[staging@platform]$ cat secrets/secure/auth-
auth-policy.json   auth-webhook.yaml
[staging@platform]$ cat secrets/secure/auth-webhook.yaml
clusters:
- name: local-auth
  cluster:
    certificate-authority: /etc/ssl/certs/platform_ca.pem
    server: https://127.0.0.1:8443/authorize/policy
users:
  - name: local-auth
current-context: webhook
contexts:
- context:
    cluster: local-auth
    user: local-auth
  name: webhook
```

```YAML
...
spec:
  containers:
  - args:
    - --region=eu-west-1
    - get
    - --output-dir=/etc/secrets
    - --bucket=some-bucket
    - --sync=true
    - --sync-interval=1m
    - --recursive=true
    - secure/
    image: quay.io/gambol99/kmsctl:v1.0.3
    name: secrets
    volumeMounts:
    - mountPath: /etc/secrets
      name: secrets
  - args:
    - --listen=127.0.0.1:8443
    - --token-file=/etc/secrets/tokens.csv
    - --auth-policy=/etc/secrets/auth-policy.json
    - --tls-cert=/etc/secrets/kubeapi.pem
    - --tls-key=/etc/secrets/kubeapi-key.pem
    image: quay.io/gambol99/kube-auth:v0.5.0
    name: kube-auth
    volumeMounts:
    - mountPath: /etc/secrets
      name: secrets
      readOnly: true
    - mountPath: /etc/ssl/certs
      name: certs
      readOnly: true
  - command:
    - /hyperkube
    - apiserver
    - --admission-control=AlwaysPullImages,NamespaceLifecycle,LimitRanger,ResourceQuota,ServiceAccount
    - --authentication-token-webhook-cache-ttl=1m
    - --authentication-token-webhook-config-file=/etc/secrets/token-webhook.yaml
    - --authorization-mode=Webhook
    - --authorization-webhook-config-file=/etc/secrets/auth-webhook.yaml
    ...
    image: quay.io/coreos/hyperkube:v1.4.7_coreos.0
    ...
    volumeMounts:
    - mountPath: /etc/secrets
      name: secrets
      readOnly: true
    - mountPath: /etc/ssl/certs
      name: certs
      readOnly: true
  ...
  volumes:
  - emptyDir: {}
    name: secrets
  - hostPath:
      path: /etc/ssl/certs
    name: certs
  - hostPath:
      path: /etc/kubernetes
    name: kubernetes
```


