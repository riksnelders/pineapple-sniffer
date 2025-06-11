#!/usr/bin/env python3
"""
WiFi Pineapple & Network Security Detector
==========================================

Updated with VPN connection details validation method
"""

import subprocess
import json
import datetime
import sys
import os
import re
import socket
import argparse
from typing import Dict, List, Optional, Tuple, Union

class PineappleDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        # Existing initialization code remains the same
    
    def validate_vpn_connection(self) -> Dict[str, Union[bool, str, Dict]]:
        """
        Validate VPN connection details and security parameters.
        
        Returns:
            Dict containing VPN connection analysis results
        """
        result = {
            'is_connected': False,
            'security_status': 'UNKNOWN',
            'details': {},
            'warnings': []
        }
        
        try:
            # Check VPN interface
            ifconfig_result = self.run_command(['ifconfig'])
            
            if ifconfig_result.get('success'):
                vpn_interfaces = ['tun', 'ppp', 'utun', 'ipsec', 'wireguard']
                for interface in vpn_interfaces:
                    if interface in ifconfig_result.get('stdout', '').lower():
                        result['is_connected'] = True
                        result['details']['vpn_interface'] = interface
                        break
            
            # Check IP configuration
            ip_result = self.run_command(['curl', '-s', 'https://ipinfo.io/json'])
            
            if ip_result.get('success'):
                try:
                    ip_data = json.loads(ip_result.get('stdout', '{}'))
                    result['details']['public_ip'] = ip_data.get('ip', 'Unknown')
                    result['details']['country'] = ip_data.get('country', 'Unknown')
                    result['details']['org'] = ip_data.get('org', 'Unknown')
                except json.JSONDecodeError:
                    result['warnings'].append("Could not parse IP information")
            
            # Check DNS leak
            dns_result = self.run_command(['cat', '/etc/resolv.conf'])
            
            if dns_result.get('success'):
                # Check if DNS servers are privacy-friendly
                privacy_dns = ['1.1.1.1', '8.8.8.8', '9.9.9.9']
                current_dns = [line.split()[-1] for line in dns_result.get('stdout', '').split('\n') if 'nameserver' in line]
                
                for dns in current_dns:
                    if not any(privacy_dns_ip in dns for privacy_dns_ip in privacy_dns):
                        result['warnings'].append(f"Potentially risky DNS server: {dns}")
            
            # Determine security status
            if result['is_connected']:
                result['security_status'] = 'SECURE' if not result['warnings'] else 'POTENTIAL_RISKS'
            
            # Log details if verbose
            if self.verbose:
                self.log(f"VPN Connection Details: {json.dumps(result, indent=2)}")
            
        except Exception as e:
            result['warnings'].append(f"VPN check failed: {str(e)}")
        
        return result
    
    # Rest of the existing PineappleDetector class remains the same...

# Existing main function and other parts of the script remain unchanged