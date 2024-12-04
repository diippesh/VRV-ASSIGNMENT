import re
import csv
from collections import defaultdict, Counter

# File names
LOG_FILE = 'sample.log'
OUTPUT_CSV = 'log_analysis_results.csv'

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Parse the log file and extract required information
def parse_log_file(file_path):
    ip_request_count = Counter()
    endpoint_access_count = Counter()
    failed_logins = defaultdict(int)
    
    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r'^([\d\.]+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_request_count[ip] += 1
            
            # Extract endpoint
            endpoint_match = re.search(r'"[A-Z]+\s(/[\w/]+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access_count[endpoint] += 1
            
            # Detect failed login attempts
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_logins[ip] += 1
    
    return ip_request_count, endpoint_access_count, failed_logins

# Save results to a CSV file
def save_to_csv(ip_requests, most_accessed, suspicious_activities, output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        
        # Requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        
        writer.writerow([])  # Empty line
        
        # Most Accessed Endpoint
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])
        
        writer.writerow([])  # Empty line
        
        # Suspicious Activities
        writer.writerow(['Suspicious Activities'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

# Main function
def main():
    # Parse the log file
    ip_requests, endpoint_access, failed_logins = parse_log_file(LOG_FILE)
    
    # Find the most frequently accessed endpoint
    most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1])
    
    # Filter suspicious activities
    suspicious_activities = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    
    # Print results to terminal
    print("Requests per IP:")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activities Detected:")
    if suspicious_activities:
        for ip, count in suspicious_activities.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")
    
    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activities, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

# Run the script
if __name__ == "__main__":
    main()
