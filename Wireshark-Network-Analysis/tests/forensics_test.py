#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wireshark Network Analysis Lab - Python Forensics Test Suite
Purpose: Executes modular unit tests and integration verifications on
         packet summary, malware scanning, and port scan detection modules.
"""

import os
import sys
import unittest
import tempfile
import json

# Insert path of parent folders
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from python.packet_summary import PacketSummaryEngine
from python.malware_detection import ThreatHuntingEngine
from python.port_scan_detection import PortScanDetector


class TestPacketSummaryEngine(unittest.TestCase):
    """Verifies PCAP metrics parsing and file exporter properties."""
    
    def setUp(self):
        # Create a mock pcap path for analysis testing
        self.temp_pcap = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        self.temp_pcap.write(b"MOCK_PCAP_BINARY_DATA_FOR_UNIT_TESTS")
        self.temp_pcap.close()

    def tearDown(self):
        if os.path.exists(self.temp_pcap.name):
            os.remove(self.temp_pcap.name)

    def test_invalid_pcap_raises_error(self):
        """Ensures non-existent files trigger a clean FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            PacketSummaryEngine("invalid_non_existent_file.pcap")

    def test_generate_report_keys(self):
        """Validates that the generated dictionary reports include all required fields."""
        engine = PacketSummaryEngine(self.temp_pcap.name)
        engine.analyze_pcap()
        report = engine.generate_report()
        
        self.assertEqual(report["pcap_file"], os.path.basename(self.temp_pcap.name))
        self.assertIn("packet_count", report)
        self.assertIn("total_bytes", report)
        self.assertIn("protocols", report)
        self.assertIn("top_talkers_source", report)
        self.assertIn("top_talkers_destination", report)

    def test_json_exporter(self):
        """Ensures the JSON exporter produces a readable and well-formatted document."""
        engine = PacketSummaryEngine(self.temp_pcap.name)
        engine.analyze_pcap()
        
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_json:
            json_path = temp_json.name
            
        try:
            engine.export_json(json_path)
            self.assertTrue(os.path.exists(json_path))
            
            with open(json_path, 'r') as f:
                data = json.load(f)
            self.assertEqual(data["pcap_file"], os.path.basename(self.temp_pcap.name))
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)


class TestThreatHuntingEngine(unittest.TestCase):
    """Verifies network intrusion scans and indicator classifications."""
    
    def setUp(self):
        self.temp_pcap = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        self.temp_pcap.write(b"MOCK_PCAP_THREATS_DATA")
        self.temp_pcap.close()

    def tearDown(self):
        if os.path.exists(self.temp_pcap.name):
            os.remove(self.temp_pcap.name)

    def test_scan_alerts_contain_indicators(self):
        """Ensures scanned alerts contain necessary MITRE and diagnostic strings."""
        hunter = ThreatHuntingEngine(self.temp_pcap.name)
        alerts = hunter.scan_pcap()
        
        self.assertGreater(len(alerts), 0, "Threat hunter should trigger default alert indications on fallback.")
        for alert in alerts:
            self.assertIn("id", alert)
            self.assertIn("type", alert)
            self.assertIn("severity", alert)
            self.assertIn("mitre", alert)
            self.assertIn("description", alert)
            self.assertIn("indicators", alert)


class TestPortScanDetector(unittest.TestCase):
    """Verifies TCP SYN half-open sweep scanners."""
    
    def setUp(self):
        self.temp_pcap = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        self.temp_pcap.write(b"MOCK_PCAP_PORT_SCAN_DATA")
        self.temp_pcap.close()

    def tearDown(self):
        if os.path.exists(self.temp_pcap.name):
            os.remove(self.temp_pcap.name)

    def test_port_scan_detection_fields(self):
        """Validates key attributes of flagged port scanners."""
        detector = PortScanDetector(self.temp_pcap.name, syn_threshold=30)
        findings = detector.scan_pcap()
        
        self.assertIn("scan_detected", findings)
        self.assertIn("attacker_ip", findings)
        self.assertIn("victim_ip", findings)
        self.assertIn("total_probed_ports", findings)
        self.assertIn("recommendation", findings)


if __name__ == '__main__':
    unittest.main()
