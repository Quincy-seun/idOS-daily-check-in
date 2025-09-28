import requests
import json
from datetime import datetime, timedelta
import os
import sys
import time
import base64
import subprocess
from typing import Optional, Dict, Any, Tuple

def clear_terminal():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def load_tokens() -> Tuple[list, list]:
    """Load access tokens and refresh tokens from files"""
    try:
        with open('bearer.txt', 'r') as file:
            access_tokens = [line.strip() for line in file if line.strip()]
        if not access_tokens:
            print("Error: bearer.txt is empty!")
            sys.exit(1)
    except FileNotFoundError:
        print("Error: bearer.txt file not found!")
        sys.exit(1)
    
    try:
        with open('refresh.txt', 'r') as file:
            refresh_tokens = [line.strip() for line in file if line.strip()]
        if not refresh_tokens:
            print("Error: refresh.txt is empty!")
            sys.exit(1)
    except FileNotFoundError:
        print("Error: refresh.txt file not found!")
        sys.exit(1)
    
    if len(access_tokens) != len(refresh_tokens):
        print("Warning: Number of access tokens and refresh tokens don't match!")
    
    return access_tokens, refresh_tokens

def load_proxies() -> list:
    """Load proxies from proxy.txt file"""
    try:
        with open('proxy.txt', 'r') as file:
            proxies = [line.strip() for line in file if line.strip()]
        return proxies
    except FileNotFoundError:
        print("Error: proxy.txt file not found!")
        return []

def get_token_expiry(token: str) -> Optional[datetime]:
    """Get token expiry datetime"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
            
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
            
        decoded = base64.urlsafe_b64decode(payload)
        payload_data = json.loads(decoded)
        
        exp = payload_data.get('exp')
        if exp:
            return datetime.fromtimestamp(exp)
        return None
        
    except Exception:
        return None

def is_token_expired(token: str) -> bool:
    """Check if token is expired or expires soon"""
    expiry = get_token_expiry(token)
    if not expiry:
        return True
    
    # Consider token expired if it expires in less than 5 minutes
    return datetime.now() >= (expiry - timedelta(minutes=5))

def get_user_id_from_token(token: str) -> Optional[str]:
    """Extract user ID from JWT token"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
            
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
            
        decoded = base64.urlsafe_b64decode(payload)
        payload_data = json.loads(decoded)
        
        return payload_data.get('userId')
    except Exception:
        return None

def refresh_access_token(refresh_token: str, proxy: Optional[str] = None) -> Optional[str]:
    """Refresh access token using refresh token"""
    print("  Refreshing access token...")
    
    url = "https://app.idos.network/api/auth/refresh"
    
    headers = {
        'authority': 'app.idos.network',
        'accept': 'application/json, text/plain, */*',
        'content-type': 'application/json',
        'origin': 'https://app.idos.network',
        'referer': 'https://app.idos.network/points',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Brave";v="140"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'sec-gpc': '1'
    }
    
    payload = {
        "refreshToken": refresh_token
    }
    
    proxies_config = None
    if proxy:
        proxies_config = {'http': proxy, 'https': proxy}
    
    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            proxies=proxies_config,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            new_access_token = data.get('accessToken')
            if new_access_token:
                print("  ✓ Token refreshed successfully")
                return new_access_token
            else:
                print("  ✗ No access token in response")
                return None
        else:
            print(f"  ✗ Refresh failed: {response.status_code} - {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"  ✗ Refresh error: {e}")
        return None

def update_token_file(token_index: int, new_token: str):
    """Update the bearer.txt file with new token"""
    try:
        with open('bearer.txt', 'r') as file:
            lines = file.readlines()
        
        if token_index < len(lines):
            lines[token_index] = new_token + '\n'
            
            with open('bearer.txt', 'w') as file:
                file.writelines(lines)
            
            print("  ✓ Token file updated")
        else:
            print("  ✗ Token index out of range")
            
    except Exception as e:
        print(f"  ✗ Error updating token file: {e}")

def make_authenticated_request(method: str, url: str, token: str, proxy: Optional[str] = None, 
                             json_data: Optional[Dict] = None) -> Dict[str, Any]:
    """Make authenticated request"""
    
    headers = {
        'authority': 'app.idos.network',
        'accept': 'application/json, text/plain, */*',
        'authorization': f'Bearer {token}',
        'content-type': 'application/json',
        'origin': 'https://app.idos.network',
        'referer': 'https://app.idos.network/points',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Brave";v="140"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'sec-gpc': '1',
        'cache-control': 'no-cache',
        'pragma': 'no-cache'
    }
    
    proxies_config = None
    if proxy:
        proxies_config = {'http': proxy, 'https': proxy}
    
    try:
        if method.upper() == 'POST':
            response = requests.post(url, headers=headers, json=json_data, 
                                   proxies=proxies_config, timeout=30)
        else:
            response = requests.get(url, headers=headers, 
                                  proxies=proxies_config, timeout=30)
        
        if response.status_code == 401:
            return {"status": "unauthorized", "code": 401, "message": "Token expired or invalid"}
        elif response.status_code == 200:
            return {"status": "success", "response": response.json()}
        else:
            return {"status": "error", "code": response.status_code, "message": response.text}
            
    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": str(e)}

def complete_daily_check(token: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    """Complete the daily check quest"""
    url = "https://app.idos.network/api/user-quests/complete"
    
    user_id = get_user_id_from_token(token)
    if not user_id:
        return {"status": "error", "message": "Could not extract user ID from token"}
    
    payload = {
        "questName": "daily_check",
        "userId": user_id
    }
    
    return make_authenticated_request('POST', url, token, proxy, payload)

def get_quest_summary(token: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    """Get quest summary for the user"""
    user_id = get_user_id_from_token(token)
    if not user_id:
        return {"status": "error", "message": "Could not extract user ID from token"}
    
    url = f"https://app.idos.network/api/user-quests/{user_id}/summary"
    
    return make_authenticated_request('GET', url, token, proxy)

def print_tabular_results(results: list):
    """Print results in a tabular format"""
    if not results:
        print("No results to display")
        return
    
    headers = ["Token #", "User ID", "Quest Name", "Completion Count", "Last Completed", "First Completed", "Status"]
    
    col_widths = [len(header) for header in headers]
    
    for i, result in enumerate(results):
        col_widths[0] = max(col_widths[0], len(str(i + 1)))
        col_widths[1] = max(col_widths[1], len(result.get('user_id', 'N/A')))
        col_widths[2] = max(col_widths[2], len(result.get('quest_name', 'N/A')))
        col_widths[3] = max(col_widths[3], len(str(result.get('completion_count', 'N/A'))))
        col_widths[4] = max(col_widths[4], len(result.get('last_completed', 'N/A')))
        col_widths[5] = max(col_widths[5], len(result.get('first_completed', 'N/A')))
        col_widths[6] = max(col_widths[6], len(result.get('status', 'N/A')))
    
    col_widths = [width + 2 for width in col_widths]
    
    header_line = "".join([headers[i].ljust(col_widths[i]) for i in range(len(headers))])
    print(header_line)
    print("-" * len(header_line))
    
    for i, result in enumerate(results):
        row = [
            str(i + 1),
            result.get('user_id', 'N/A'),
            result.get('quest_name', 'N/A'),
            str(result.get('completion_count', 'N/A')),
            result.get('last_completed', 'N/A'),
            result.get('first_completed', 'N/A'),
            result.get('status', 'N/A')
        ]
        row_line = "".join([row[j].ljust(col_widths[j]) for j in range(len(row))])
        print(row_line)

def process_account(access_token: str, refresh_token: str, token_index: int, 
                   proxy: Optional[str] = None) -> Dict[str, Any]:
    """Process a single account"""
    current_token = access_token
    user_id = get_user_id_from_token(current_token)
    
    # Refresh token if needed
    if is_token_expired(current_token):
        print(f"  Token expired, refreshing...")
        new_token = refresh_access_token(refresh_token, proxy)
        if new_token:
            current_token = new_token
            update_token_file(token_index, new_token)
        else:
            return {
                'user_id': user_id or 'Unknown',
                'status': 'Token refresh failed'
            }
    
    # Complete daily check
    print("  Completing daily check...")
    completion_result = complete_daily_check(current_token, proxy)
    
    if completion_result.get('status') == 'unauthorized':
        print("  Daily check failed: Unauthorized")
        return {
            'user_id': user_id or 'Unknown',
            'status': 'Unauthorized - Please check tokens'
        }
    
    # Get quest summary
    print("  Fetching quest summary...")
    summary_result = get_quest_summary(current_token, proxy)
    
    result_data = {
        'user_id': user_id or 'Unknown',
        'status': 'Unknown'
    }
    
    if summary_result.get('status') == 'success':
        summary_data = summary_result.get('response', [])
        daily_check_found = False
        
        for quest in summary_data:
            if quest.get('questName') == 'daily_check':
                result_data.update({
                    'quest_name': quest.get('questName'),
                    'completion_count': quest.get('completionCount', 0),
                    'last_completed': quest.get('lastCompletedAt', '').replace('T', ' ').split('.')[0] if quest.get('lastCompletedAt') else 'Never',
                    'first_completed': quest.get('firstCompletedAt', '').replace('T', ' ').split('.')[0] if quest.get('firstCompletedAt') else 'Never',
                    'status': 'Success' if completion_result.get('status') == 'success' else 'Check completed but summary failed'
                })
                daily_check_found = True
                break
        
        if not daily_check_found:
            result_data.update({
                'quest_name': 'daily_check',
                'completion_count': 0,
                'last_completed': 'Never',
                'first_completed': 'Never',
                'status': 'Daily check not found in profile'
            })
    else:
        result_data['status'] = f"Error: {summary_result.get('message', 'Unknown error')}"
    
    return result_data

def main_loop():
    """Main function with 25-hour loop"""
    clear_terminal()
    
    print("IDOS Network Daily Check Script")
    print("=" * 50)
    print("This script will run for 25 hours with automatic token refresh")
    print("=" * 50)
    
    # Load tokens and proxies
    access_tokens, refresh_tokens = load_tokens()
    print(f"Loaded {len(access_tokens)} account(s)")
    
    use_proxy = input("Use proxy? (y/n): ").lower().strip() == 'y'
    
    proxies = []
    if use_proxy:
        proxies = load_proxies()
        if proxies:
            print(f"Loaded {len(proxies)} proxy/proxies")
        else:
            print("No proxies loaded, continuing without proxy")
            use_proxy = False
    
    # Calculate 25 hours in seconds
    total_duration = 25 * 60 * 60  # 25 hours in seconds
    start_time = datetime.now()
    end_time = start_time + timedelta(hours=25)
    
    print(f"\nScript started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Will run until: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nPress Ctrl+C to stop the script early\n")
    
    iteration = 0
    
    try:
        while datetime.now() < end_time:
            iteration += 1
            current_time = datetime.now()
            time_remaining = end_time - current_time
            
            clear_terminal()
            print(f"IDOS Network Daily Check - Iteration {iteration}")
            print("=" * 50)
            print(f"Current time: {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Time remaining: {str(time_remaining).split('.')[0]}")
            print("=" * 50)
            
            results = []
            
            for i, (access_token, refresh_token) in enumerate(zip(access_tokens, refresh_tokens)):
                print(f"\nProcessing account {i + 1}/{len(access_tokens)}...")
                
                proxy = proxies[i % len(proxies)] if use_proxy and proxies else None
                
                result = process_account(access_token, refresh_token, i, proxy)
                results.append(result)
                
                print(f"  User: {result['user_id']} - Status: {result['status']}")
                
                # Small delay between accounts
                time.sleep(2)
            
            # Display results
            print("\n" + "=" * 50)
            print(f"ITERATION {iteration} RESULTS")
            print("=" * 50)
            print_tabular_results(results)
            
            # Calculate next run time (24 hours from now)
            next_run = current_time + timedelta(hours=24)
            time_until_next = next_run - datetime.now()
            
            print(f"\nNext iteration at: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Sleeping for: {str(time_until_next).split('.')[0]}")
            
            # Sleep until next day (with small interruptions to check for Ctrl+C)
            sleep_seconds = time_until_next.total_seconds()
            while sleep_seconds > 0:
                # Sleep in chunks to allow for Ctrl+C
                chunk = min(300, sleep_seconds)  # 5 minute chunks
                time.sleep(chunk)
                sleep_seconds -= chunk
                
                # Update display
                if sleep_seconds > 0:
                    clear_terminal()
                    hours_remaining = sleep_seconds / 3600
                    print(f"Sleeping... {hours_remaining:.1f} hours remaining")
                    print("Press Ctrl+C to stop")
            
            # Reload tokens for next iteration (in case they were updated)
            access_tokens, refresh_tokens = load_tokens()
            
    except KeyboardInterrupt:
        print(f"\n\nScript stopped by user at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Completed {iteration} iteration(s)")
    
    print(f"\nScript completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main_loop()
