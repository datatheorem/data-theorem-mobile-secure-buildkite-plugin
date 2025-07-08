#!/usr/bin/env bats

load "$BATS_PLUGIN_PATH/load.bash"

# Uncomment the following line to debug stub failures
# export BUILDKITE_AGENT_STUB_DEBUG=/dev/tty
# export CURL_STUB_DEBUG=/dev/tty

@test "Creates annotation when no vulnerabilities found" {
  export DT_UPLOAD_API_KEY="test-upload-key"
  export DT_MOBILE_RESULTS_API_KEY="test-results-key"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BINARY_PATH="/tmp/test.apk"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_POLL_SCAN_RESULTS="true"

  # Create mock APK file
  touch "/tmp/test.apk"

  # Mock curl responses
  stub curl \
    'echo "{\"upload_url\":\"https://upload.example.com/test\"}200"' \
    'echo "{\"mobile_app_id\":\"app123\",\"scan_id\":\"scan456\"}200"' \
    'echo "{\"static_scan\":{\"status\":\"COMPLETED\"},\"start_date\":\"2023-01-01T00:00:00Z\"}200"' \
    'echo "{\"pagination_information\":{\"total_count\":0}}200"'

  # Mock jq to parse JSON responses
  stub jq \
    '-r .upload_url : echo https://upload.example.com/test' \
    '-r .mobile_app_id : echo app123' \
    '-r .scan_id : echo scan456' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 0'

  # Mock buildkite-agent annotate command
  stub buildkite-agent 'annotate "**Data Theorem Mobile Security Scan Results**<br/>✅ No security findings found" --style "success" : echo "Annotation created: No security findings found"'

  run "$PWD/hooks/command"

  assert_success
  assert_output --partial "PASSED: No security findings found"
  assert_output --partial "Annotation created: No security findings found"

  unstub curl
  unstub jq
  unstub buildkite-agent
  
  # Clean up
  rm -f "/tmp/test.apk"
}

@test "Creates annotation when vulnerabilities found with blocking severity" {
  export DT_UPLOAD_API_KEY="test-upload-key"
  export DT_MOBILE_RESULTS_API_KEY="test-results-key"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BINARY_PATH="/tmp/test.apk"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BLOCK_ON_SEVERITY="HIGH"

  # Create mock APK file
  touch "/tmp/test.apk"

  # Mock curl responses
  stub curl \
    'echo "{\"upload_url\":\"https://upload.example.com/test\"}200"' \
    'echo "{\"mobile_app_id\":\"app123\",\"scan_id\":\"scan456\"}200"' \
    'echo "{\"static_scan\":{\"status\":\"COMPLETED\"},\"start_date\":\"2023-01-01T00:00:00Z\"}200"' \
    'echo "{\"pagination_information\":{\"total_count\":3}}200"'

  # Mock jq to parse JSON responses
  stub jq \
    '-r .upload_url : echo https://upload.example.com/test' \
    '-r .mobile_app_id : echo app123' \
    '-r .scan_id : echo scan456' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 3'

  # Mock buildkite-agent annotate command
  stub buildkite-agent 'annotate "**Data Theorem Mobile Security Scan Results**<br/>Found **3** vulnerabilities at or above **HIGH** severity level<br/>[View Results](https://www.securetheorem.com/mobile-secure/v2/security/)" --style "error" : echo "Annotation created: Found 3 HIGH severity vulnerabilities"'

  run "$PWD/hooks/command"

  assert_failure
  assert_output --partial "FAILED: Found 3 vulnerabilities at or above HIGH severity level"
  assert_output --partial "Annotation created: Found 3 HIGH severity vulnerabilities"

  unstub curl
  unstub jq
  unstub buildkite-agent
  
  # Clean up
  rm -f "/tmp/test.apk"
}

