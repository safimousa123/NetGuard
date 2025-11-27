#!/usr/bin/env python3
"""
Email Setup Script
User-friendly configuration for network scanner email notifications
"""

import sys
import getpass
from pathlib import Path
from notifications import EmailNotifier

def print_header():
    print("=" * 60)
    print("  NETWORK SCANNER - EMAIL NOTIFICATION SETUP")
    print("=" * 60)
    print()

def get_email_provider_settings():
    """Get SMTP settings based on email provider"""
    providers = {
        "1": {"name": "Gmail", "server": "smtp.gmail.com", "port": 587, "tls": True},
        "2": {"name": "Outlook/Hotmail", "server": "smtp-mail.outlook.com", "port": 587, "tls": True},
        "3": {"name": "Yahoo Mail", "server": "smtp.mail.yahoo.com", "port": 587, "tls": True},
        "4": {"name": "Custom SMTP", "server": "", "port": 587, "tls": True}
    }
    
    print("Select your email provider:")
    for key, provider in providers.items():
        print(f"  {key}. {provider['name']}")
    print()
    
    while True:
        choice = input("Enter choice (1-4): ").strip()
        if choice in providers:
            return providers[choice]
        print("Invalid choice. Please enter 1, 2, 3, or 4.")

def get_custom_smtp_settings():
    """Get custom SMTP server settings"""
    print("\nCustom SMTP Configuration:")
    server = input("SMTP server (e.g., mail.yourdomain.com): ").strip()
    
    while True:
        try:
            port = int(input("SMTP port (usually 587 or 25): ").strip())
            if 1 <= port <= 65535:
                break
            print("Port must be between 1 and 65535.")
        except ValueError:
            print("Please enter a valid port number.")
    
    use_tls = input("Use TLS encryption? (y/n) [y]: ").strip().lower()
    tls = use_tls != 'n'
    
    return {"name": "Custom", "server": server, "port": port, "tls": tls}

def get_email_credentials(provider_name):
    """Get email credentials from user"""
    print(f"\n{provider_name} Credentials:")
    
    username = input("Email address: ").strip()
    
    if provider_name == "Gmail":
        print("\nIMPORTANT: For Gmail, you need an App Password, not your regular password.")
        print("Steps to create App Password:")
        print("1. Enable 2-Factor Authentication on your Google account")
        print("2. Go to https://myaccount.google.com/apppasswords")
        print("3. Generate an app password for 'Mail'")
        print("4. Use that 16-character password below")
        print()
    
    password = getpass.getpass("Password (App Password for Gmail): ")
    
    return username, password

def get_recipients():
    """Get list of notification recipients"""
    print("\nNotification Recipients:")
    print("Enter email addresses that should receive scan notifications.")
    print("You can add multiple recipients (press Enter after each, empty line to finish):")
    
    recipients = []
    while True:
        email = input(f"Recipient {len(recipients) + 1} (or press Enter to finish): ").strip()
        if not email:
            break
        if '@' in email and '.' in email.split('@')[1]:
            recipients.append(email)
            print(f"  Added: {email}")
        else:
            print("  Invalid email format. Please try again.")
    
    if not recipients:
        print("No recipients added. Notifications will be disabled.")
    
    return recipients

def get_notification_preferences():
    """Get notification preferences"""
    print("\nNotification Preferences:")
    print("Choose which events should trigger email notifications:")
    
    preferences = {}
    
    options = [
        ("scan_complete", "Scan completion reports", True),
        ("new_critical_cve", "Critical vulnerability alerts", True),
        ("new_high_cve", "High severity vulnerability alerts", False),
        ("new_host", "New host detection", True),
        ("scan_failure", "Scan failure alerts", True),
        ("weekly_summary", "Weekly security summaries", True)
    ]
    
    for key, description, default in options:
        default_str = "Y" if default else "N"
        response = input(f"  {description} (y/n) [{default_str}]: ").strip().lower()
        
        if response == '':
            preferences[key] = default
        else:
            preferences[key] = response.startswith('y')
    
    return preferences

def test_email_configuration(notifier):
    """Test the email configuration"""
    print("\nTesting email configuration...")
    
    success, message = notifier.test_connection()
    
    if success:
        print("✅ Email configuration test successful!")
        
        send_test = input("Send a test notification email? (y/n) [y]: ").strip().lower()
        if send_test != 'n':
            test_sent = notifier._send_email(
                subject="Network Scanner - Test Notification",
                content="This is a test email from your Network Scanner. If you receive this, email notifications are working correctly!",
                is_html=False
            )
            
            if test_sent:
                print("✅ Test email sent successfully!")
            else:
                print("❌ Failed to send test email.")
    else:
        print(f"❌ Email configuration test failed: {message}")
        print("\nPlease check your settings and try again.")
        return False
    
    return True

def main():
    print_header()
    
    try:
        # Initialize notifier
        notifier = EmailNotifier()
        
        # Get email provider settings
        provider = get_email_provider_settings()
        
        if provider["name"] == "Custom":
            provider = get_custom_smtp_settings()
        
        # Get credentials
        username, password = get_email_credentials(provider["name"])
        
        # Get recipients
        recipients = get_recipients()
        
        if not recipients:
            print("\nNo recipients configured. Email notifications will be disabled.")
            enable_email = False
        else:
            enable_email = True
        
        # Get notification preferences
        if enable_email:
            preferences = get_notification_preferences()
        
        # Configure the notifier
        if enable_email:
            notifier.configure_email(
                smtp_server=provider["server"],
                smtp_port=provider["port"],
                username=username,
                password=password,
                from_email=username,
                recipients=recipients,
                use_tls=provider["tls"]
            )
            
            # Update notification triggers
            notifier.config["notification_triggers"].update(preferences)
            notifier.save_config()
            
            print(f"\n✅ Email notifications configured successfully!")
            print(f"   Server: {provider['server']}:{provider['port']}")
            print(f"   From: {username}")
            print(f"   Recipients: {len(recipients)} configured")
            
            # Test configuration
            if not test_email_configuration(notifier):
                print("\nConfiguration saved, but testing failed.")
                print("You can run this setup again to fix any issues.")
                return 1
        else:
            # Disable email notifications
            notifier.config["enabled"] = False
            notifier.save_config()
            print("Email notifications disabled.")
        
        print(f"\nConfiguration saved to: {notifier.config_file}")
        print("\nYour network scanner will now send email notifications when:")
        
        if enable_email:
            for key, enabled in preferences.items():
                if enabled:
                    descriptions = {
                        "scan_complete": "• Scans complete",
                        "new_critical_cve": "• Critical vulnerabilities are found",
                        "new_high_cve": "• High severity vulnerabilities are found",
                        "new_host": "• New hosts are discovered",
                        "scan_failure": "• Scans fail",
                        "weekly_summary": "• Weekly summaries are generated"
                    }
                    print(descriptions.get(key, f"• {key} events occur"))
        else:
            print("• Email notifications are disabled")
        
        print("\nSetup complete! 🚀")
        return 0
        
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
        return 1
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
