#!/usr/bin/env python3
import sys
import cv2
from pyzbar import pyzbar
import re

def extract_totp_from_qr(image_path):
    """Extract TOTP secret from QR code image"""
    try:
        # Read the image
        image = cv2.imread(image_path)
        if image is None:
            print(f"Error: Could not load image from {image_path}")
            return None
        
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Decode QR codes
        decoded_objects = pyzbar.decode(gray)
        
        if not decoded_objects:
            print("No QR code found in the image")
            return None
        
        # Process decoded objects
        for obj in decoded_objects:
            data = obj.data.decode('utf-8')
            
            # Try to extract TOTP information
            totp_info = extract_totp_info(data)
            if totp_info:
                return totp_info
        
        print("No TOTP data found in QR code")
        return None
        
    except Exception as e:
        print(f"Error processing QR code: {str(e)}")
        return None

def extract_totp_info(data):
    """Extract TOTP information from QR code data"""
    # Check if it's a TOTP URI
    if data.startswith('otpauth://totp/'):
        # Extract secret
        secret_match = re.search(r'secret=([^&]+)', data)
        secret = secret_match.group(1) if secret_match else None
        
        # Extract issuer
        issuer_match = re.search(r'issuer=([^&]+)', data)
        issuer = issuer_match.group(1) if issuer_match else None
        
        # Extract account name
        account_match = re.search(r'totp/([^?]+)', data)
        account = account_match.group(1) if account_match else None
        
        if account and ':' in account:
            # Some formats use "issuer:account"
            parts = account.split(':', 1)
            if not issuer:
                issuer = parts[0]
            account = parts[1] if len(parts) > 1 else parts[0]
        
        return {
            'secret': secret,
            'issuer': issuer,
            'account': account,
            'full_uri': data
        }
    
    # Check if it's just a base32 secret
    elif re.match(r'^[A-Z2-7]+=*$', data):
        return {
            'secret': data,
            'note': 'Raw TOTP secret'
        }
    
    return None

def main():
    if len(sys.argv) != 2:
        print("Usage: qr_to_totp.py <image_path>")
        sys.exit(1)
    
    image_path = sys.argv[1]
    result = extract_totp_from_qr(image_path)
    
    if result:
        #print("TOTP Information Extracted:")
        for key, value in result.items():
            print(f"{key}: {value}")
        
        # For easy copying, print just the secret
        #if 'secret' in result:
        #    print(f"\nSecret only: {result['secret']}")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
