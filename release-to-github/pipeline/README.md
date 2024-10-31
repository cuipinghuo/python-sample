# release-to-github

Tekton release pipeline to release the source code extracted from the image built with Konflux, to GitHub.

## Parameters

| Name                 | Description                                        | Optional | Default value |
|----------------------|----------------------------------------------------|----------|---------------|
| verify_ec_task_bundle | The location of the bundle containing the verify-enterprise-contract task | Yes       | "quay.io/enterprise-contract/ec-task-bundle:2fdddbbfdf5f2ba251a70b6378847a2b3630da4b"             |
| enterpriseContractPolicy         | EnterpriseContractPolicy that needs to be executed      | Yes      |"enterprise-contract-service/default"            |
| enterpriseContractExtraRuleData         | Extra rule data to be merged into the policy specified in params.enterpriseContractPolicy. Use syntax "key1=value1,key2=value2..."      | Yes      | "pipeline_intention=release"            |
| enterpriseContractTimeout         | Timeout setting for `ec validate`      | Yes      | 40m0s            |
| release         | The namespaced name (namespace/name) of the Release      | No      | -            |
| releasePlan         | The namespaced name (namespace/name) of the ReleasePlan      | No      | -            |
| snapshot         | The namespaced name (namespace/name) of the Snapshot      | No      | -            |
| taskGitUrl         | The url to the git repo where the release-service-catalog tasks to be used are stored      | Yes      | "https://github.com/dheerajodha/the-mentalist-quiz.git"            |
| taskGitRevision         | The revision in the taskGitUrl repo to be used      | Yes      | "create-gh-release-pipeline"            |
