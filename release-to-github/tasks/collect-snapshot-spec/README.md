# collect-snapshot-spec

Tekton task to collect .spec data from the Snapshot

A task result is returned for the snapshot resource with the relative path to the stored JSON for it in the workspace.

## Parameters

| Name                 | Description                                        | Optional | Default value |
|----------------------|----------------------------------------------------|----------|---------------|
| snapshot             | Namespaced name of the Snapshot                    | No       | -             |
| subdirectory         | Subdirectory inside the workspace to be used.      | Yes      | ""            |

## Results

| Name         | Description                                                        |
|--------------|--------------------------------------------------------------------|
| snapshotSpec | The relative path in the workspace to the stored snapshotSpec json |
