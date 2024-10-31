# create-github-release

Tekton task that creates a release in GitHub.com via the API.

## Parameters

| Name            | Description                                                         | Optional | Default value |
|-----------------|---------------------------------------------------------------------|----------|---------------|
| repository      | The github repository's name where the release should be created    | No       | -             |
| username        | The github username of the repo where the release should be created | No       | -             |
| release_version | The version string of the new release                               | No       | -             |
| commit_sha      | The commit SHA that triggered build in Konflux                      | No       | -             |
| release_author  | The username of the release creator/requester                       | No       | -             |

## Results

| Name            | Description                                 |
|-----------------|---------------------------------------------|
| release_url      | Release URL to inspect the created release |
