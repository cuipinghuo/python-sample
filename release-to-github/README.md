## Steps to create automated Releases to GitHub

1. Create a `ServiceAccount`

* [Your (Tenant) Release Pipeline](https://konflux-ci.dev/docs/advanced-how-tos/releasing/tenant-release-pipelines/) needs access to some resources in order to create releases.
* For this, we need to create a ServiceAccount and link it with the pipeline via ReleasePlan (created in next step)
* Run the following command to create a ServiceAccount named `my-serviceaccount` within your namespace:

```
oc create serviceaccount my-serviceaccount -n <your-namespace-goes-here>
```

2. Create a `ReleasePlan`

* Now, create a ReleasePlan for your application which uses the above ServiceAccount and points to the Release pipline stored in this directory.
* Run the following command to create it:

```
oc apply -f - <<EOF
apiVersion: appstudio.redhat.com/v1alpha1
kind: ReleasePlan
metadata:
  labels:
    release.appstudio.openshift.io/auto-release: 'true'
    release.appstudio.openshift.io/standing-attribution: 'true'
  name: my-releaseplan
  namespace: <your-namespace-goes-here>
spec:
  application: <your-application-name-goes-here>
  pipeline:
    serviceAccountName: my-serviceaccount 
    pipelineRef: # (Optional) replace with wherever your release pipeline lives
      resolver: git
      params:
        - name: url
          value: "https://github.com/cuipinghuo/python-sample.git"
        - name: revision
          value: main
        - name: pathInRepo
          value: "release-to-github/pipeline/release-to-github.yaml"
EOF
```

3. Create a `Role`

* In order to give your Release Pipeline permission to interact with specific resources that are required to create Releases, we need to create a Role containing those permission.
* Run the following command to create it:

```
oc apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: <your-namespace-goes-here>
  name: my-role
rules:
- apiGroups: ["appstudio.redhat.com"]
  resources: ["releases", "releaseplans", "snapshots"]
  verbs: ["get", "list", "create", "update"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
EOF

```

4. Create a `RoleBinding`

* Now, to bind the above Role to the ServiceAccount we created in Step 1, we need to create a RoleBinding.
* Run the following command to create it:

```
oc apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: my-rolebinding
  namespace: <your-namespace-goes-here>
subjects:
- kind: ServiceAccount
  name: my-serviceaccount
  namespace: <your-namespace-goes-here>
roleRef:
  kind: Role
  name: my-role
  apiGroup: rbac.authorization.k8s.io
EOF

```

5. Create a `Secret`

* The release task needs access to a secret named `my-github-secret` that contains your GitHub token.
* This token is needed to authorize the GitHub POST API call to create the Releases.
* Run the following command to create it:

```
oc apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: my-github-secret
type: Opaque
data:
  token: $(echo -n '<your-github-token-goes-here>' | base64)
EOF

```

Now, as soon your merge a PR that passes all the tests, you're all set to receive automated Releases in your GitHub repo!