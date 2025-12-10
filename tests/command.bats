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
    '-r .status : echo ' \
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

@test "Creates annotation when vulnerabilities found with blocking severity HIGH" {
  export DT_UPLOAD_API_KEY="test-upload-key"
  export DT_MOBILE_RESULTS_API_KEY="test-results-key"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BINARY_PATH="/tmp/test.apk"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BLOCK_ON_SEVERITY="HIGH"

  # Create mock APK file
  touch "/tmp/test.apk"

  # Mock curl responses - HIGH severity only makes 1 call
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
    '-r .status : echo ' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 3'

  # Mock buildkite-agent annotate command
  stub buildkite-agent 'annotate "**Data Theorem Mobile Security Scan Results**<br/>Found **3** vulnerabilities in this scan at or above **HIGH** severity level<br/>[View Results](https://www.securetheorem.com/mobile-secure/v2/security/)" --style "error" : echo "Annotation created: Found 3 HIGH severity vulnerabilities"'

  run "$PWD/hooks/command"

  assert_failure
  assert_output --partial "FAILED: Found 3 vulnerabilities in this scan at or above HIGH severity level"
  assert_output --partial "Annotation created: Found 3 HIGH severity vulnerabilities"

  unstub curl
  unstub jq
  unstub buildkite-agent

  # Clean up
  rm -f "/tmp/test.apk"
}

@test "Creates annotation when vulnerabilities found with blocking severity MEDIUM" {
  export DT_UPLOAD_API_KEY="test-upload-key"
  export DT_MOBILE_RESULTS_API_KEY="test-results-key"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BINARY_PATH="/tmp/test.apk"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BLOCK_ON_SEVERITY="MEDIUM"

  # Create mock APK file
  touch "/tmp/test.apk"

  # Mock curl responses - MEDIUM severity makes 2 calls (HIGH + MEDIUM)
  stub curl \
    'echo "{\"upload_url\":\"https://upload.example.com/test\"}200"' \
    'echo "{\"mobile_app_id\":\"app123\",\"scan_id\":\"scan456\"}200"' \
    'echo "{\"static_scan\":{\"status\":\"COMPLETED\"},\"start_date\":\"2023-01-01T00:00:00Z\"}200"' \
    'echo "{\"pagination_information\":{\"total_count\":2}}200"' \
    'echo "{\"pagination_information\":{\"total_count\":3}}200"'

  # Mock jq to parse JSON responses
  stub jq \
    '-r .upload_url : echo https://upload.example.com/test' \
    '-r .mobile_app_id : echo app123' \
    '-r .scan_id : echo scan456' \
    '-r .status : echo ' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 2' \
    '-r .pagination_information.total_count : echo 3'

  # Mock buildkite-agent annotate command
  stub buildkite-agent 'annotate "**Data Theorem Mobile Security Scan Results**<br/>Found **5** vulnerabilities in this scan at or above **MEDIUM** severity level<br/>[View Results](https://www.securetheorem.com/mobile-secure/v2/security/)" --style "error" : echo "Annotation created: Found 5 MEDIUM severity vulnerabilities"'

  run "$PWD/hooks/command"

  assert_failure
  assert_output --partial "FAILED: Found 5 vulnerabilities in this scan at or above MEDIUM severity level"
  assert_output --partial "Annotation created: Found 5 MEDIUM severity vulnerabilities"

  unstub curl
  unstub jq
  unstub buildkite-agent

  # Clean up
  rm -f "/tmp/test.apk"
}

@test "Creates annotation when vulnerabilities found with blocking severity LOW" {
  export DT_UPLOAD_API_KEY="test-upload-key"
  export DT_MOBILE_RESULTS_API_KEY="test-results-key"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BINARY_PATH="/tmp/test.apk"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BLOCK_ON_SEVERITY="LOW"

  # Create mock APK file
  touch "/tmp/test.apk"

  # Mock curl responses - LOW severity makes 3 calls (HIGH + MEDIUM + LOW)
  stub curl \
    'echo "{\"upload_url\":\"https://upload.example.com/test\"}200"' \
    'echo "{\"mobile_app_id\":\"app123\",\"scan_id\":\"scan456\"}200"' \
    'echo "{\"static_scan\":{\"status\":\"COMPLETED\"},\"start_date\":\"2023-01-01T00:00:00Z\"}200"' \
    'echo "{\"pagination_information\":{\"total_count\":1}}200"' \
    'echo "{\"pagination_information\":{\"total_count\":2}}200"' \
    'echo "{\"pagination_information\":{\"total_count\":4}}200"'

  # Mock jq to parse JSON responses
  stub jq \
    '-r .upload_url : echo https://upload.example.com/test' \
    '-r .mobile_app_id : echo app123' \
    '-r .scan_id : echo scan456' \
    '-r .status : echo ' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 1' \
    '-r .pagination_information.total_count : echo 2' \
    '-r .pagination_information.total_count : echo 4'

  # Mock buildkite-agent annotate command
  stub buildkite-agent 'annotate "**Data Theorem Mobile Security Scan Results**<br/>Found **7** vulnerabilities in this scan at or above **LOW** severity level<br/>[View Results](https://www.securetheorem.com/mobile-secure/v2/security/)" --style "error" : echo "Annotation created: Found 7 LOW severity vulnerabilities"'

  run "$PWD/hooks/command"

  assert_failure
  assert_output --partial "FAILED: Found 7 vulnerabilities in this scan at or above LOW severity level"
  assert_output --partial "Annotation created: Found 7 LOW severity vulnerabilities"

  unstub curl
  unstub jq
  unstub buildkite-agent

  # Clean up
  rm -f "/tmp/test.apk"
}

@test "Creates annotation when no vulnerabilities found with blocking severity" {
  export DT_UPLOAD_API_KEY="test-upload-key"
  export DT_MOBILE_RESULTS_API_KEY="test-results-key"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BINARY_PATH="/tmp/test.apk"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BLOCK_ON_SEVERITY="HIGH"

  # Create mock APK file
  touch "/tmp/test.apk"

  # Mock curl responses - HIGH severity with 0 vulnerabilities
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
    '-r .status : echo ' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 0'

  # Mock buildkite-agent annotate command
  stub buildkite-agent 'annotate "**Data Theorem Mobile Security Scan Results**<br/>✅ No vulnerabilities found at or above **HIGH** severity level" --style "success" : echo "Annotation created: No HIGH severity vulnerabilities found"'

  run "$PWD/hooks/command"

  assert_success
  assert_output --partial "PASSED: No vulnerabilities found at or above HIGH severity level"
  assert_output --partial "Annotation created: No HIGH severity vulnerabilities found"

  unstub curl
  unstub jq
  unstub buildkite-agent

  # Clean up
  rm -f "/tmp/test.apk"
}

@test "Multiple API calls validation for MEDIUM severity" {
  export DT_UPLOAD_API_KEY="test-upload-key"
  export DT_MOBILE_RESULTS_API_KEY="test-results-key"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BINARY_PATH="/tmp/test.apk"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BLOCK_ON_SEVERITY="MEDIUM"

  # Create mock APK file
  touch "/tmp/test.apk"

  # Mock curl responses - MEDIUM severity should make exactly 2 API calls
  # First 3 calls are for upload and scan status, then 2 calls for HIGH and MEDIUM severity
  stub curl \
    'echo "{\"upload_url\":\"https://upload.example.com/test\"}200"' \
    'echo "{\"mobile_app_id\":\"app123\",\"scan_id\":\"scan456\"}200"' \
    'echo "{\"static_scan\":{\"status\":\"COMPLETED\"},\"start_date\":\"2023-01-01T00:00:00Z\"}200"' \
    'echo "{\"pagination_information\":{\"total_count\":1}}200"' \
    'echo "{\"pagination_information\":{\"total_count\":2}}200"'

  # Mock jq to parse JSON responses
  stub jq \
    '-r .upload_url : echo https://upload.example.com/test' \
    '-r .mobile_app_id : echo app123' \
    '-r .scan_id : echo scan456' \
    '-r .status : echo ' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 1' \
    '-r .pagination_information.total_count : echo 2'

  # Mock buildkite-agent annotate command - total should be 1+2=3
  stub buildkite-agent 'annotate "**Data Theorem Mobile Security Scan Results**<br/>Found **3** vulnerabilities in this scan at or above **MEDIUM** severity level<br/>[View Results](https://www.securetheorem.com/mobile-secure/v2/security/)" --style "error" : echo "Annotation created: Found 3 MEDIUM severity vulnerabilities"'

  run "$PWD/hooks/command"

  assert_failure
  assert_output --partial "FAILED: Found 3 vulnerabilities in this scan at or above MEDIUM severity level"

  unstub curl
  unstub jq
  unstub buildkite-agent

  # Clean up
  rm -f "/tmp/test.apk"
}

@test "WARN_ON_SEVERITY does not fail build" {
  export DT_UPLOAD_API_KEY="test-upload-key"
  export DT_MOBILE_RESULTS_API_KEY="test-results-key"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BINARY_PATH="/tmp/test.apk"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_WARN_ON_SEVERITY="HIGH"

  # Create mock APK file
  touch "/tmp/test.apk"

  # Mock curl responses
  stub curl \
    'echo "{\"upload_url\":\"https://upload.example.com/test\"}200"' \
    'echo "{\"mobile_app_id\":\"app123\",\"scan_id\":\"scan456\"}200"' \
    'echo "{\"static_scan\":{\"status\":\"COMPLETED\"},\"start_date\":\"2023-01-01T00:00:00Z\"}200"' \
    'echo "{\"pagination_information\":{\"total_count\":2}}200"'

  # Mock jq to parse JSON responses
  stub jq \
    '-r .upload_url : echo https://upload.example.com/test' \
    '-r .mobile_app_id : echo app123' \
    '-r .scan_id : echo scan456' \
    '-r .status : echo ' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 2'

  run "$PWD/hooks/command"

  assert_success
  assert_output --partial "WARNING: Found 2 security findings for scan scan456 at or above HIGH severity level"

  unstub curl
  unstub jq

  # Clean up
  rm -f "/tmp/test.apk"
}

@test "WAIT_FOR_STATIC_SCAN_ONLY checks static_scan status" {
  export DT_UPLOAD_API_KEY="test-upload-key"
  export DT_MOBILE_RESULTS_API_KEY="test-results-key"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BINARY_PATH="/tmp/test.apk"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_POLL_SCAN_RESULTS="true"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_WAIT_FOR_STATIC_SCAN_ONLY="true"

  # Create mock APK file
  touch "/tmp/test.apk"

  # Mock curl responses
  stub curl \
    'echo "{\"upload_url\":\"https://upload.example.com/test\"}200"' \
    'echo "{\"mobile_app_id\":\"app123\",\"scan_id\":\"scan456\"}200"' \
    'echo "{\"status\":\"IN_PROGRESS\",\"static_scan\":{\"status\":\"COMPLETED\"},\"start_date\":\"2023-01-01T00:00:00Z\"}200"' \
    'echo "{\"pagination_information\":{\"total_count\":0}}200"'

  # Mock jq to parse JSON responses
  stub jq \
    '-r .upload_url : echo https://upload.example.com/test' \
    '-r .mobile_app_id : echo app123' \
    '-r .scan_id : echo scan456' \
    '-r .status : echo ' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 0'

  # Mock buildkite-agent annotate command
  stub buildkite-agent 'annotate "**Data Theorem Mobile Security Scan Results**<br/>✅ No security findings found" --style "success" : echo "Annotation created: No security findings found"'

  run "$PWD/hooks/command"

  assert_success
  assert_output --partial "WAIT_FOR_STATIC_SCAN_ONLY is enabled"
  assert_output --partial "Scan completed successfully"

  unstub curl
  unstub jq
  unstub buildkite-agent

  # Clean up
  rm -f "/tmp/test.apk"
}

@test "SEVERITY_CHECK_SCOPE ALL_ISSUES checks all open issues" {
  export DT_UPLOAD_API_KEY="test-upload-key"
  export DT_MOBILE_RESULTS_API_KEY="test-results-key"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BINARY_PATH="/tmp/test.apk"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BLOCK_ON_SEVERITY="HIGH"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_SEVERITY_CHECK_SCOPE="ALL_ISSUES"

  # Create mock APK file
  touch "/tmp/test.apk"

  # Mock curl responses - for ALL_ISSUES, results_since should NOT be included
  stub curl \
    'echo "{\"upload_url\":\"https://upload.example.com/test\"}200"' \
    'echo "{\"mobile_app_id\":\"app123\",\"scan_id\":\"scan456\"}200"' \
    'echo "{\"static_scan\":{\"status\":\"COMPLETED\"},\"start_date\":\"2023-01-01T00:00:00Z\"}200"' \
    'echo "{\"pagination_information\":{\"total_count\":5}}200"'

  # Mock jq to parse JSON responses
  stub jq \
    '-r .upload_url : echo https://upload.example.com/test' \
    '-r .mobile_app_id : echo app123' \
    '-r .scan_id : echo scan456' \
    '-r .status : echo ' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 5'

  # Mock buildkite-agent annotate command
  stub buildkite-agent 'annotate "**Data Theorem Mobile Security Scan Results**<br/>Found **5** vulnerabilities in the mobile app at or above **HIGH** severity level<br/>[View Results](https://www.securetheorem.com/mobile-secure/v2/security/)" --style "error" : echo "Annotation created"'

  run "$PWD/hooks/command"

  assert_failure
  assert_output --partial "SEVERITY_CHECK_SCOPE is set to ALL_ISSUES"
  assert_output --partial "FAILED: Found 5 vulnerabilities in the mobile app at or above HIGH severity level"

  unstub curl
  unstub jq
  unstub buildkite-agent

  # Clean up
  rm -f "/tmp/test.apk"
}

@test "Glob pattern support with multiple files" {
  export DT_UPLOAD_API_KEY="test-upload-key"
  export DT_MOBILE_RESULTS_API_KEY="test-results-key"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_BINARY_PATH="/tmp/test-*.apk"
  export BUILDKITE_PLUGIN_DATA_THEOREM_MOBILE_SECURE_POLL_SCAN_RESULTS="true"

  # Create mock APK files
  touch "/tmp/test-1.apk" "/tmp/test-2.apk"

  # Mock curl responses for 2 file uploads
  stub curl \
    'echo "{\"upload_url\":\"https://upload.example.com/test1\"}200"' \
    'echo "{\"mobile_app_id\":\"app123\",\"scan_id\":\"scan456\"}200"' \
    'echo "{\"upload_url\":\"https://upload.example.com/test2\"}200"' \
    'echo "{\"mobile_app_id\":\"app123\",\"scan_id\":\"scan789\"}200"' \
    'echo "{\"static_scan\":{\"status\":\"COMPLETED\"},\"start_date\":\"2023-01-01T00:00:00Z\"}200"' \
    'echo "{\"pagination_information\":{\"total_count\":0}}200"' \
    'echo "{\"static_scan\":{\"status\":\"COMPLETED\"},\"start_date\":\"2023-01-01T00:00:00Z\"}200"' \
    'echo "{\"pagination_information\":{\"total_count\":0}}200"'

  # Mock jq to parse JSON responses
  stub jq \
    '-r .upload_url : echo https://upload.example.com/test1' \
    '-r .mobile_app_id : echo app123' \
    '-r .scan_id : echo scan456' \
    '-r .upload_url : echo https://upload.example.com/test2' \
    '-r .mobile_app_id : echo app123' \
    '-r .scan_id : echo scan789' \
    '-r .status : echo ' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 0' \
    '-r .status : echo ' \
    '-r .static_scan.status : echo COMPLETED' \
    '-r .start_date : echo 2023-01-01T00:00:00Z' \
    '-r .pagination_information.total_count : echo 0'

  # Mock buildkite-agent annotate command
  stub buildkite-agent \
    'annotate "**Data Theorem Mobile Security Scan Results**<br/>✅ No security findings found" --style "success" : echo "Annotation created"' \
    'annotate "**Data Theorem Mobile Security Scan Results**<br/>✅ No security findings found" --style "success" : echo "Annotation created"'

  run "$PWD/hooks/command"

  assert_success
  assert_output --partial "Found 2 file(s) to upload"
  assert_output --partial "Successfully uploaded 2 file(s)"

  unstub curl
  unstub jq
  unstub buildkite-agent

  # Clean up
  rm -f "/tmp/test-1.apk" "/tmp/test-2.apk"
}


