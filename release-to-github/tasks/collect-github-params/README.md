# collect-github-params

Tekton task that collects GitHub configuration options to prepare for release.

## Parameters

| Name         | Description                                                      | Optional | Default value |
|--------------|------------------------------------------------------------------|----------|---------------|
| snapshotPath | Path to the Snapshot file                                        | No       | -             |

## Results

| Name            | Description                                                      |
|-----------------|------------------------------------------------------------------|
| repository      | The github repository where the release should be created        |
| release_version | The version string of the new release                            |
| username        | The username of the repo where release will be created           |
| commit_sha      | The commit SHA that triggered the build in Konflux"              |
