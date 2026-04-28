from dynamic_analyzer.traffic_capture import parse_captured_traffic

test_data = {
    "flows": [
        {
            "url": "http://127.0.0.1:8888/getaccounts",
            "method": "POST",
            "request": {
                "body": "username=admin&password=admin%40123"
            }
        }
    ]
}

findings = parse_captured_traffic(test_data)
print(f"Findings: {findings}")
