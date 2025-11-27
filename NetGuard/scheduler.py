#!/usr/bin/env python3
"""
Professional Scheduler for Network Scanner
Handles automated vulnerability scanning with flexible scheduling
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
import schedule

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/scheduler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetworkScannerScheduler:
    def __init__(self, config_file="config/scheduler_config.json"):
        self.config_file = Path(config_file)
        self.config = {}
        self.running = False
        self.scheduler_thread = None
        
        # Ensure directories exist
        self.config_file.parent.mkdir(exist_ok=True)
        Path("logs").mkdir(exist_ok=True)
        
        # Load existing configuration
        self.load_config()
        
        logger.info("Network Scanner Scheduler initialized")
    
    def load_config(self):
        """Load scheduler configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                logger.info(f"Loaded configuration from {self.config_file}")
            else:
                self.config = {
                    "schedules": [],
                    "scanner_path": "main.py",
                    "default_options": "--mode fast --use-api",
                    "notifications": {
                        "enabled": True,
                        "file_alerts": True,
                        "email_alerts": False
                    },
                    "retention": {
                        "keep_logs_days": 30,
                        "keep_reports_days": 90
                    }
                }
                self.save_config()
                logger.info("Created default configuration")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.config = {}
    
    def save_config(self):
        """Save scheduler configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4, default=str)
            logger.info("Configuration saved")
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def add_schedule(self, name, network, scan_options="", frequency="weekly", 
                    day_of_week="sunday", time_str="02:00", enabled=True):
        """Add a new scheduled scan"""
        
        schedule_entry = {
            "id": len(self.config.get("schedules", [])) + 1,
            "name": name,
            "network": network,
            "scan_options": scan_options or self.config.get("default_options", "--mode fast"),
            "frequency": frequency,  # daily, weekly, monthly
            "day_of_week": day_of_week.lower(),  # monday, tuesday, etc.
            "time": time_str,  # HH:MM format
            "enabled": enabled,
            "created": datetime.now().isoformat(),
            "last_run": None,
            "next_run": None,
            "run_count": 0
        }
        
        if "schedules" not in self.config:
            self.config["schedules"] = []
        
        self.config["schedules"].append(schedule_entry)
        self.save_config()
        
        logger.info(f"Added schedule '{name}': {frequency} {day_of_week} at {time_str}")
        return schedule_entry["id"]
    
    def remove_schedule(self, schedule_id):
        """Remove a scheduled scan"""
        if "schedules" not in self.config:
            return False
        
        original_count = len(self.config["schedules"])
        self.config["schedules"] = [
            s for s in self.config["schedules"] 
            if s["id"] != schedule_id
        ]
        
        if len(self.config["schedules"]) < original_count:
            self.save_config()
            logger.info(f"Removed schedule ID {schedule_id}")
            return True
        return False
    
    def enable_schedule(self, schedule_id, enabled=True):
        """Enable or disable a scheduled scan"""
        for schedule_item in self.config.get("schedules", []):
            if schedule_item["id"] == schedule_id:
                schedule_item["enabled"] = enabled
                self.save_config()
                status = "enabled" if enabled else "disabled"
                logger.info(f"Schedule '{schedule_item['name']}' {status}")
                return True
        return False
    
    def list_schedules(self):
        """List all scheduled scans"""
        schedules = self.config.get("schedules", [])
        if not schedules:
            print("📅 No scheduled scans configured")
            return
        
        print("📅 Scheduled Scans:")
        print("=" * 80)
        for schedule_item in schedules:
            status = "✅ Active" if schedule_item["enabled"] else "❌ Disabled"
            last_run = schedule_item.get("last_run")
            if last_run and last_run != "Never":
                try:
                    last_run = datetime.fromisoformat(last_run).strftime("%Y-%m-%d %H:%M")
                except (ValueError, TypeError):
                    last_run = "Never"
            else:
                last_run = "Never"
            
            print(f"ID: {schedule_item['id']}")
            print(f"Name: {schedule_item['name']}")
            print(f"Network: {schedule_item['network']}")
            print(f"Schedule: {schedule_item['frequency']} {schedule_item['day_of_week']} at {schedule_item['time']}")
            print(f"Status: {status}")
            print(f"Last Run: {last_run}")
            print(f"Run Count: {schedule_item.get('run_count', 0)}")
            print("-" * 40)
    
    def calculate_next_run_time(self, schedule_item):
        """Calculate when the next scan should run"""
        try:
            now = datetime.now()
            time_parts = schedule_item["time"].split(":")
            target_hour = int(time_parts[0])
            target_minute = int(time_parts[1])
            
            if schedule_item["frequency"] == "daily":
                next_run = now.replace(hour=target_hour, minute=target_minute, second=0, microsecond=0)
                if next_run <= now:
                    next_run += timedelta(days=1)
            
            elif schedule_item["frequency"] == "weekly":
                days_of_week = {
                    'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3,
                    'friday': 4, 'saturday': 5, 'sunday': 6
                }
                target_weekday = days_of_week.get(schedule_item["day_of_week"], 6)
                
                days_ahead = target_weekday - now.weekday()
                if days_ahead <= 0:  # Target day already happened this week
                    days_ahead += 7
                
                next_run = now + timedelta(days=days_ahead)
                next_run = next_run.replace(hour=target_hour, minute=target_minute, second=0, microsecond=0)
            
            else:  # monthly - first day of next month
                if now.month == 12:
                    next_run = datetime(now.year + 1, 1, 1, target_hour, target_minute)
                else:
                    next_run = datetime(now.year, now.month + 1, 1, target_hour, target_minute)
            
            return next_run
            
        except Exception as e:
            logger.error(f"Error calculating next run time: {e}")
            return None
    
    def execute_scan(self, schedule_item):
        """Execute a scheduled scan"""
        try:
            logger.info(f"🚀 Starting scheduled scan: {schedule_item['name']}")
            
            # Build command
            scan_command = [
                sys.executable,
                self.config.get("scanner_path", "main.py"),
                "--range", schedule_item["network"]
            ]
            
            # Add scan options
            if schedule_item.get("scan_options"):
                scan_command.extend(schedule_item["scan_options"].split())
            
            # Add timestamp to output filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_prefix = f"reports/scheduled_scan_{schedule_item['name']}_{timestamp}"
            scan_command.extend(["--output", output_prefix])
            
            logger.info(f"Executing: {' '.join(scan_command)}")
            
            # Execute scan
            start_time = datetime.now()
            result = subprocess.run(
                scan_command,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Update schedule stats
            schedule_item["last_run"] = start_time.isoformat()
            schedule_item["run_count"] = schedule_item.get("run_count", 0) + 1
            self.save_config()
            
            if result.returncode == 0:
                logger.info(f"✅ Scan completed successfully in {duration:.1f} seconds")
                self.send_notification(
                    f"Scheduled scan '{schedule_item['name']}' completed successfully",
                    f"Duration: {duration:.1f} seconds\nNetwork: {schedule_item['network']}\nReport: {output_prefix}.html"
                )
            else:
                logger.error(f"❌ Scan failed with return code {result.returncode}")
                logger.error(f"Error output: {result.stderr}")
                self.send_notification(
                    f"Scheduled scan '{schedule_item['name']}' FAILED",
                    f"Error: {result.stderr}\nNetwork: {schedule_item['network']}"
                )
                
        except subprocess.TimeoutExpired:
            logger.error(f"⏰ Scan timed out after 1 hour")
            self.send_notification(
                f"Scheduled scan '{schedule_item['name']}' TIMED OUT",
                f"Scan exceeded 1 hour timeout\nNetwork: {schedule_item['network']}"
            )
        except Exception as e:
            logger.error(f"💥 Scan execution failed: {e}")
            self.send_notification(
                f"Scheduled scan '{schedule_item['name']}' ERROR",
                f"Exception: {str(e)}\nNetwork: {schedule_item['network']}"
            )
    
    def send_notification(self, title, message):
        """Send notification about scan results"""
        try:
            notifications_config = self.config.get("notifications", {})
            
            # File-based notification
            if notifications_config.get("file_alerts", True):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                alert_file = Path(f"logs/alert_{timestamp}.txt")
                
                with open(alert_file, 'w') as f:
                    f.write(f"ALERT: {title}\n")
                    f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Details:\n{message}\n")
                
                logger.info(f"📄 Alert saved to {alert_file}")
            
            # TODO: Email notifications will be added later
            if notifications_config.get("email_alerts", False):
                logger.info("📧 Email notifications not yet implemented")
                
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
    
    def setup_schedule_jobs(self):
        """Set up all enabled schedule jobs"""
        schedule.clear()  # Clear existing jobs
        
        for schedule_item in self.config.get("schedules", []):
            if not schedule_item.get("enabled", True):
                continue
            
            try:
                if schedule_item["frequency"] == "daily":
                    schedule.every().day.at(schedule_item["time"]).do(
                        self.execute_scan, schedule_item
                    )
                elif schedule_item["frequency"] == "weekly":
                    day_func = getattr(schedule.every(), schedule_item["day_of_week"])
                    day_func.at(schedule_item["time"]).do(
                        self.execute_scan, schedule_item
                    )
                elif schedule_item["frequency"] == "monthly":
                    # For monthly, we'll check daily and execute on first of month
                    schedule.every().day.at(schedule_item["time"]).do(
                        self.check_monthly_execution, schedule_item
                    )
                
                logger.info(f"📅 Scheduled: {schedule_item['name']} - {schedule_item['frequency']} {schedule_item.get('day_of_week', '')} at {schedule_item['time']}")
                
            except Exception as e:
                logger.error(f"Error setting up schedule for {schedule_item['name']}: {e}")
    
    def check_monthly_execution(self, schedule_item):
        """Check if monthly scan should run today"""
        today = datetime.now()
        if today.day == 1:  # First day of month
            self.execute_scan(schedule_item)
    
    def run_scheduler(self):
        """Main scheduler loop"""
        logger.info("🚀 Network Scanner Scheduler started")
        self.running = True
        
        # Set up all scheduled jobs
        self.setup_schedule_jobs()
        
        try:
            while self.running:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
                
        except KeyboardInterrupt:
            logger.info("⏹️ Scheduler stopped by user")
        except Exception as e:
            logger.error(f"💥 Scheduler error: {e}")
        finally:
            self.running = False
            logger.info("🛑 Network Scanner Scheduler stopped")
    
    def start_scheduler(self, daemon=True):
        """Start scheduler in background thread"""
        if self.running:
            logger.warning("Scheduler is already running")
            return False
        
        if daemon:
            self.scheduler_thread = threading.Thread(target=self.run_scheduler, daemon=True)
            self.scheduler_thread.start()
            logger.info("📅 Scheduler started in background")
        else:
            self.run_scheduler()
        
        return True
    
    def stop_scheduler(self):
        """Stop the scheduler"""
        if self.running:
            self.running = False
            if self.scheduler_thread:
                self.scheduler_thread.join(timeout=5)
            logger.info("🛑 Scheduler stopped")
            return True
        return False
    
    def get_status(self):
        """Get scheduler status and next run times"""
        status = {
            "running": self.running,
            "schedules_count": len(self.config.get("schedules", [])),
            "active_schedules": len([s for s in self.config.get("schedules", []) if s.get("enabled", True)]),
            "next_runs": []
        }
        
        for schedule_item in self.config.get("schedules", []):
            if schedule_item.get("enabled", True):
                next_run = self.calculate_next_run_time(schedule_item)
                status["next_runs"].append({
                    "name": schedule_item["name"],
                    "network": schedule_item["network"],
                    "next_run": next_run.isoformat() if next_run else "Unknown"
                })
        
        return status

def main():
    parser = argparse.ArgumentParser(
        description="Professional Network Scanner Scheduler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Set up weekly Sunday scan
  python3 scheduler.py --add-weekly --name "Home Network" --network "192.168.1.0/24" --day sunday --time "02:00"
  
  # Set up daily quick scan
  python3 scheduler.py --add-daily --name "Critical Servers" --network "10.0.0.1-10" --time "06:00" --options "--mode fast"
  
  # Start scheduler service
  python3 scheduler.py --start
  
  # Check status
  python3 scheduler.py --status
        """
    )
    
    # Configuration commands
    config_group = parser.add_argument_group('Schedule Management')
    config_group.add_argument('--add-daily', action='store_true', help='Add daily scan schedule')
    config_group.add_argument('--add-weekly', action='store_true', help='Add weekly scan schedule')
    config_group.add_argument('--add-monthly', action='store_true', help='Add monthly scan schedule')
    config_group.add_argument('--remove', type=int, metavar='ID', help='Remove schedule by ID')
    config_group.add_argument('--enable', type=int, metavar='ID', help='Enable schedule by ID')
    config_group.add_argument('--disable', type=int, metavar='ID', help='Disable schedule by ID')
    
    # Schedule parameters
    params_group = parser.add_argument_group('Schedule Parameters')
    params_group.add_argument('--name', required=False, help='Schedule name')
    params_group.add_argument('--network', required=False, help='Network to scan (IP range)')
    params_group.add_argument('--day', choices=['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'], 
                             default='sunday', help='Day of week for weekly scans')
    params_group.add_argument('--time', default='02:00', help='Time to run scan (HH:MM format)')
    params_group.add_argument('--options', default='', help='Additional scanner options')
    
    # Control commands
    control_group = parser.add_argument_group('Scheduler Control')
    control_group.add_argument('--start', action='store_true', help='Start scheduler service')
    control_group.add_argument('--stop', action='store_true', help='Stop scheduler service')
    control_group.add_argument('--status', action='store_true', help='Show scheduler status')
    control_group.add_argument('--list', action='store_true', help='List all schedules')
    
    args = parser.parse_args()
    
    # Initialize scheduler
    scheduler = NetworkScannerScheduler()
    
    # Handle commands
    if args.add_daily or args.add_weekly or args.add_monthly:
        if not args.name or not args.network:
            print("❌ --name and --network are required for adding schedules")
            return 1
        
        frequency = "daily" if args.add_daily else ("weekly" if args.add_weekly else "monthly")
        schedule_id = scheduler.add_schedule(
            name=args.name,
            network=args.network,
            scan_options=args.options,
            frequency=frequency,
            day_of_week=args.day,
            time_str=args.time
        )
        print(f"✅ Added {frequency} schedule '{args.name}' with ID {schedule_id}")
    
    elif args.remove:
        if scheduler.remove_schedule(args.remove):
            print(f"✅ Removed schedule ID {args.remove}")
        else:
            print(f"❌ Schedule ID {args.remove} not found")
    
    elif args.enable:
        if scheduler.enable_schedule(args.enable, True):
            print(f"✅ Enabled schedule ID {args.enable}")
        else:
            print(f"❌ Schedule ID {args.enable} not found")
    
    elif args.disable:
        if scheduler.enable_schedule(args.disable, False):
            print(f"✅ Disabled schedule ID {args.disable}")
        else:
            print(f"❌ Schedule ID {args.disable} not found")
    
    elif args.list:
        scheduler.list_schedules()
    
    elif args.status:
        status = scheduler.get_status()
        print("📊 Scheduler Status:")
        print(f"Running: {'✅ Yes' if status['running'] else '❌ No'}")
        print(f"Total Schedules: {status['schedules_count']}")
        print(f"Active Schedules: {status['active_schedules']}")
        
        if status['next_runs']:
            print("\n📅 Next Scheduled Runs:")
            for run_info in status['next_runs']:
                next_run = datetime.fromisoformat(run_info['next_run']).strftime('%Y-%m-%d %H:%M')
                print(f"• {run_info['name']}: {next_run} ({run_info['network']})")
    
    elif args.start:
        print("🚀 Starting Network Scanner Scheduler...")
        print("Press Ctrl+C to stop")
        scheduler.start_scheduler(daemon=False)
    
    elif args.stop:
        if scheduler.stop_scheduler():
            print("🛑 Scheduler stopped")
        else:
            print("ℹ️ Scheduler was not running")
    
    else:
        parser.print_help()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
