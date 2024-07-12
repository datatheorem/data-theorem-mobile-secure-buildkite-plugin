# Data Theorem Mobile Secure BuildKite Plugin

Data Theorem's Mobile Secure will scan each pre-production release automatically (up to 7000 releases/day)
for security & privacy issues using static, dynamic, and behavioral analysis for both iOS and Android applications.

More information can be found here:  
https://www.datatheorem.com/products/mobile-secure

## Example

Add the following to your `pipeline.yml`:

```yml
steps:
  - label: "Build Mobile App Binary"
    # replace this step with your own logix to build the pre-prod mobile binary that you want to scan
    command: "echo 'Example mobile binary build step...'"

  - label: "Upload Mobile App Binary to Data Theorem for scanning"
    plugins:
      - datatheorem/data-theorem-mobile-secure:
          UPLOAD_API_KEY: $(buildkite-agent secret get DT_UPLOAD_API_KEY)
          SIGNED_BINARY_PATH: "app-debug.apk" # path to the pre-prod mobile binary built in the previous step
```

Optionally, you can configure the plugin to wait for the scan to complete
To do this, add the extra flag `POLL_SCAN_RESULTS: true`
This mode will also require to set up a Data Theorem Mobile Results API Key
It can be retrieved or created at [DevSecOps -> Data Theorem Results API](https://www.securetheorem.com/devsecops/v2/results_api_access)
And set it as a secret accessible to your BuildKite pipeline.

```yml
steps:
  - label: "Build Mobile App Binary"
    # replace this step with your own logix to build the pre-prod mobile binary that you want to scan
    command: "echo 'Example mobile binary build step...'"

  - label: "Upload Mobile App Binary to Data Theorem for scanning"
    plugins:
      - datatheorem/data-theorem-mobile-secure:
          UPLOAD_API_KEY: $(buildkite-agent secret get DT_UPLOAD_API_KEY)
          SIGNED_BINARY_PATH: "app-debug.apk" # path to the pre-prod mobile binary built in the previous step
          POLL_SCAN_RESULTS: true
          MOBILE_RESULTS_API_KEY: $(buildkite-agent secret get DT_MOBILE_RESULTS_API_KEY)
```

## Configuration

### `UPLOAD_API_KEY` (Required, string)
API Key you can retrieve in the Data theorem Portal [DevSecOps -> Scan via CI/CD](https://www.securetheorem.com/devsecops/v2/scancicd)

Hard-coding the raw value of the API key is not recommended for security reasons.
We recommend using [BuildKite Secrets](https://buildkite.com/docs/pipelines/security/secrets/buildkite-secrets)

- On your agent cluster, define a secret named `DT_UPLOAD_API_KEY` and set the value to what you have retrieved from the Data Theorem Portal
- In the BuildKite pipeline definition, you can pass the API Key as `UPLOAD_API_KEY: $(buildkite-agent secret get DT_UPLOAD_API_KEY)` in the plugin's inputs

### `SIGNED_BINARY_PATH` (Required, string)
Path to the Mobile App binary file that has been built and should be sent for scanning

### `SOURCEMAP_PATH` (Optional, string)
Optionally, you can upload a sourcemap file for de-obfuscation