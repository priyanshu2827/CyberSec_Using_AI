import requests
import sys
import json
from datetime import datetime

class CybersecurityAPITester:
    def __init__(self, base_url="https://b5cfbab7-b8fc-4930-a39d-71b7792b6fae.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.created_scenario_id = None

    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}" if endpoint else f"{self.api_url}/"
        if headers is None:
            headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=30)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ PASS - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    print(f"   Response: {json.dumps(response_data, indent=2)[:200]}...")
                    return True, response_data
                except:
                    return True, {}
            else:
                print(f"❌ FAIL - Expected {expected_status}, got {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data}")
                except:
                    print(f"   Error text: {response.text}")
                return False, {}

        except Exception as e:
            print(f"❌ FAIL - Exception: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test GET /api/ endpoint"""
        success, response = self.run_test(
            "Root API Endpoint",
            "GET",
            "",
            200
        )
        if success and 'message' in response:
            print(f"   ✓ Message found: {response['message']}")
            return True
        return False

    def test_create_scenario(self):
        """Test POST /api/scenarios endpoint"""
        sample_scenario = {
            "name": f"Test Scenario {datetime.now().strftime('%H%M%S')}",
            "description": "A test scenario for API validation",
            "severity": "high",
            "tactics": ["Initial Access", "Execution"],
            "techniques": ["T1566", "T1059"]
        }
        
        success, response = self.run_test(
            "Create Scenario",
            "POST",
            "scenarios",
            200,
            data=sample_scenario
        )
        
        if success and 'id' in response:
            self.created_scenario_id = response['id']
            print(f"   ✓ Scenario created with ID: {self.created_scenario_id}")
            return True
        return False

    def test_list_scenarios(self):
        """Test GET /api/scenarios endpoint"""
        success, response = self.run_test(
            "List Scenarios",
            "GET",
            "scenarios",
            200
        )
        
        if success and isinstance(response, list):
            print(f"   ✓ Found {len(response)} scenarios")
            if self.created_scenario_id:
                found = any(s.get('id') == self.created_scenario_id for s in response)
                if found:
                    print(f"   ✓ Created scenario found in list")
                else:
                    print(f"   ⚠️  Created scenario not found in list")
            return True
        return False

    def test_run_simulation(self):
        """Test POST /api/simulate endpoint"""
        if not self.created_scenario_id:
            print("❌ Cannot test simulation - no scenario ID available")
            return False

        sample_telemetry = {
            "device_id": "WORKSTATION-TEST",
            "timestamp": "2025-01-01T00:00:00Z",
            "network_connections": [
                {
                    "source_ip": "192.168.1.10",
                    "destination_ip": "203.0.113.10",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "bytes_transferred": 150000000,
                    "destination_domain": "temp-malicious.biz"
                },
                {
                    "source_ip": "192.168.1.10",
                    "destination_ip": "192.168.1.5",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "bytes_transferred": 2000
                }
            ],
            "process_list": [
                {
                    "name": "powershell.exe",
                    "pid": 1234,
                    "command_line": "powershell -ExecutionPolicy Bypass -enc AAA",
                    "network_connections": 15
                }
            ],
            "file_access_logs": [],
            "system_metrics": {"cpu_usage": 75.0},
            "security_events": []
        }

        simulation_data = {
            "scenario_id": self.created_scenario_id,
            "telemetry": sample_telemetry
        }

        success, response = self.run_test(
            "Run Simulation",
            "POST",
            "simulate",
            200,
            data=simulation_data
        )

        if success:
            # Validate response structure
            required_fields = ['id', 'scenario_id', 'device_id', 'risk_score', 'indicators', 'blocked_actions']
            missing_fields = [field for field in required_fields if field not in response]
            
            if missing_fields:
                print(f"   ❌ Missing required fields: {missing_fields}")
                return False
            
            # Validate risk_score range
            risk_score = response.get('risk_score', -1)
            if not (0 <= risk_score <= 10):
                print(f"   ❌ Risk score {risk_score} not in range [0,10]")
                return False
            
            # Validate indicators array
            indicators = response.get('indicators', [])
            if not isinstance(indicators, list):
                print(f"   ❌ Indicators should be an array")
                return False
            
            # Validate blocked_actions array exists
            blocked_actions = response.get('blocked_actions', None)
            if blocked_actions is None:
                print(f"   ❌ blocked_actions field missing")
                return False
            
            print(f"   ✓ Risk score: {risk_score}/10")
            print(f"   ✓ Indicators count: {len(indicators)}")
            print(f"   ✓ Blocked actions count: {len(blocked_actions)}")
            
            return True
        return False

    def test_list_simulations(self):
        """Test GET /api/simulations endpoint"""
        success, response = self.run_test(
            "List Simulations",
            "GET",
            "simulations",
            200
        )
        
        if success and isinstance(response, list):
            print(f"   ✓ Found {len(response)} simulations")
            if len(response) > 0:
                print(f"   ✓ Latest simulation device: {response[0].get('device_id', 'N/A')}")
            return True
        return False

def main():
    print("🚀 Starting Cybersecurity API Tests")
    print("=" * 50)
    
    tester = CybersecurityAPITester()
    
    # Run all tests in sequence
    tests = [
        ("Root Endpoint", tester.test_root_endpoint),
        ("Create Scenario", tester.test_create_scenario),
        ("List Scenarios", tester.test_list_scenarios),
        ("Run Simulation", tester.test_run_simulation),
        ("List Simulations", tester.test_list_simulations),
    ]
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            test_func()
        except Exception as e:
            print(f"❌ Test {test_name} failed with exception: {str(e)}")
    
    # Print final results
    print(f"\n{'='*50}")
    print(f"📊 FINAL RESULTS")
    print(f"Tests Run: {tester.tests_run}")
    print(f"Tests Passed: {tester.tests_passed}")
    print(f"Success Rate: {(tester.tests_passed/tester.tests_run*100):.1f}%" if tester.tests_run > 0 else "0%")
    
    if tester.tests_passed == tester.tests_run:
        print("🎉 ALL TESTS PASSED!")
        return 0
    else:
        print("❌ SOME TESTS FAILED!")
        return 1

if __name__ == "__main__":
    sys.exit(main())