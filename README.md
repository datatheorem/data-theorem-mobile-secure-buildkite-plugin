# Data Theorem Mobile Secure BuildKite Plugin

Data Theorem's Mobile Secure will scan each pre-production release automatically (up to 7000 releases/day)
for security & privacy issues using static, dynamic, and behavioral analysis for both iOS and Android applications.

More information can be found here:  
https://www.datatheorem.com/products/mobile-secure

## Examples

### Basic Example
Add the following to your `pipeline.yml`:

```yml
steps:
  - label: "Build Mobile App Binary"
    # replace this step with your own logic to build the pre-prod mobile binary that you want to scan
    command: "echo 'Example mobile binary build step...'"

  - label: "Upload Mobile App Binary to Data Theorem for scanning"
    plugins:
      - datatheorem/data-theorem-mobile-secure:
          UPLOAD_API_KEY: $(buildkite-agent secret get DT_UPLOAD_API_KEY)
          BINARY_PATH: "app-debug.apk" # path to the pre-prod mobile binary built in the previous step
```

### Example with optional `SOURCEMAP_PATH`:
An optional Java mapping.txt file for deobfuscating Android binaries.

```yml
steps:
  - label: "Build Mobile App Binary"
    # replace this step with your own logic to build the pre-prod mobile binary that you want to scan
    command: "echo 'Example mobile binary build step...'"

  - label: "Upload Mobile App Binary to Data Theorem for scanning"
    plugins:
      - datatheorem/data-theorem-mobile-secure:
          UPLOAD_API_KEY: $(buildkite-agent secret get DT_UPLOAD_API_KEY)
          BINARY_PATH: "app-debug.apk" # path to the pre-prod mobile binary built in the previous step
          SOURCEMAP_PATH: "mapping.txt" # path to mapping.txt
```

### Example with scan result polling
Optionally, you can configure the plugin to wait for the scan to complete and print out the number of new security findings.
To do this, add the extra flag `POLL_SCAN_RESULTS: true`
This mode will also require to set up a Data Theorem Mobile Results API Key
It can be retrieved or created at [DevSecOps -> Data Theorem Results API](https://www.securetheorem.com/devsecops/v2/results_api_access)
And set it as a secret accessible to your BuildKite pipeline.

```yml
steps:
  - label: "Build Mobile App Binary"
    # replace this step with your own logic to build the pre-prod mobile binary that you want to scan
    command: "echo 'Example mobile binary build step...'"

  - label: "Upload Mobile App Binary to Data Theorem for scanning"
    plugins:
      - datatheorem/data-theorem-mobile-secure:
          UPLOAD_API_KEY: $(buildkite-agent secret get DT_UPLOAD_API_KEY)
          BINARY_PATH: "app-debug.apk" # path to the pre-prod mobile binary built in the previous step
          POLL_SCAN_RESULTS: true
          MOBILE_RESULTS_API_KEY: $(buildkite-agent secret get DT_MOBILE_RESULTS_API_KEY)
```

The plugin's logs should look like this for a successful scan with no discovered security issues
![buildkite-data-theorem-mobile-secure-plugin-polling-mode-no-issues.png](images%2Fbuildkite-data-theorem-mobile-secure-plugin-polling-mode-no-issues.png)

### Example with vulnerability blocking
The plugin supports automatic build blocking based on security findings. When `BLOCK_ON_SEVERITY` is specified, the plugin will automatically enable polling and block the build if any vulnerabilities are found at or above the specified severity level.

```yml
steps:
  - label: "Build Mobile App Binary"
    # replace this step with your own logic to build the pre-prod mobile binary that you want to scan
    command: "echo 'Example mobile binary build step...'"

  - label: "Upload Mobile App Binary to Data Theorem for scanning"
    plugins:
      - datatheorem/data-theorem-mobile-secure:
          UPLOAD_API_KEY: $(buildkite-agent secret get DT_UPLOAD_API_KEY)
          BINARY_PATH: "app-debug.apk" # path to the pre-prod mobile binary built in the previous step
          BLOCK_ON_SEVERITY: "HIGH" # Block build on HIGH severity vulnerabilities
          MOBILE_RESULTS_API_KEY: $(buildkite-agent secret get DT_MOBILE_RESULTS_API_KEY)
```

## Vulnerability Blocking
The plugin supports automatic build blocking based on security findings. When `BLOCK_ON_SEVERITY` is specified, the plugin will:

1. Wait for the scan to complete (default: 5 minutes, configurable via `POLLING_TIMEOUT`)
2. Check for security findings at or above the specified severity level
3. Block the build if any vulnerabilities are found at the minimum severity threshold

**Important:** Vulnerability blocking requires a separate `MOBILE_RESULTS_API_KEY` with results access permissions.

### Severity Levels
- `HIGH`: Block on high severity vulnerabilities only
- `MEDIUM`: Block on medium and high severity vulnerabilities
- `LOW`: Block on all severity vulnerabilities (low, medium, high)

## Configuration

### `UPLOAD_API_KEY` (Required, string)
API Key you can retrieve in the Data theorem Portal [DevSecOps -> Scan via CI/CD](https://www.securetheorem.com/devsecops/v2/scancicd)

Hard-coding the raw value of the API key is not recommended for security reasons.
We recommend using [BuildKite Secrets](https://buildkite.com/docs/pipelines/security/secrets/buildkite-secrets)

- On your agent cluster, define a secret named `DT_UPLOAD_API_KEY` and set the value to what you have retrieved from the Data Theorem Portal
- In the BuildKite pipeline definition, you can pass the API Key as `UPLOAD_API_KEY: $(buildkite-agent secret get DT_UPLOAD_API_KEY)` in the plugin's inputs

### `BINARY_PATH` (Required, string)
Path to the mobile binary (APK, IPA, APPX or XAP) to be scanned.

### `SOURCEMAP_PATH` (Optional, string)
An optional path to a Java mapping.txt file for deobfuscating Android binaries.
Note: Once deobfuscation is enabled for PRE_PROD or ENTERPRISE Android app, future uploads of the same app will also require a mapping file.
See [How To Enable De-obfuscation of Android Scan Results Using A Mapping File](https://datatheorem.atlassian.net/servicedesk/customer/portal/1/article/61669389) for more information.

### `POLL_SCAN_RESULTS` (Optional, boolean)
When set to `true`, the plugin will poll for the scan's status until completion and print if the scan has found any new issues
This requires a Data Theorem Mobile Results API Key to be set (see below)

### `MOBILE_RESULTS_API_KEY` (Optional, string)
API Key you can retrieve in the Data theorem Portal [DevSecOps -> Data Theorem Results API](https://www.securetheorem.com/devsecops/v2/results_api_access)
This is only required if you want to poll for scan results instead of exiting after starting the scan.

Hard-coding the raw value of the API key is not recommended for security reasons.
We recommend using [BuildKite Secrets](https://buildkite.com/docs/pipelines/security/secrets/buildkite-secrets)

- On your agent cluster, define a secret named `DT_MOBILE_RESULTS_API_KEY` and set the value to what you have retrieved from the Data Theorem Portal
- In the BuildKite pipeline definition, you can pass the API Key as `MOBILE_RESULTS_API_KEY: $(buildkite-agent secret get DT_MOBILE_RESULTS_API_KEY)` in the plugin's inputs

### `BLOCK_ON_SEVERITY` (Optional, string)
Block the build if vulnerabilities are found at or above the specified severity level. When set, the plugin will automatically enable polling and require `MOBILE_RESULTS_API_KEY`.

Supported values:
- `HIGH`: Block on high severity vulnerabilities only
- `MEDIUM`: Block on medium and high severity vulnerabilities
- `LOW`: Block on all severity vulnerabilities (low, medium, high)

### `POLLING_TIMEOUT` (Optional, number)
Timeout duration in seconds for polling scan results. Default is 300 seconds (5 minutes).
This parameter only applies when `POLL_SCAN_RESULTS` is `true` or when `BLOCK_ON_SEVERITY` is set.

Example:
```yml
POLLING_TIMEOUT: 600  # Wait up to 10 minutes for scan results
```

It should look like this in your Buildkite agent secret settings
![buildkite-data-theorem-mobile-secure-plugin-secrets.png](images%2Fbuildkite-data-theorem-mobile-secure-plugin-secrets.png)

## Contributing

### Running Tests

To test the plugin, use the Buildkite plugin tester:

```bash
docker run -it --rm -v "$PWD:/plugin:ro" buildkite/plugin-tester
```