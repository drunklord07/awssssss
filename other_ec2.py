import boto3
import pandas as pd
import json
import os
import base64
import datetime
import time
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- CONFIGURATION ---
OUTPUT_EXCEL = "ec2_ultimate_inventory.xlsx"
DATA_DIR = "ec2_instance_details"  # Folder for detailed JSON files
MAX_WORKERS = 20  # Adjust based on your internet connection/CPU

# Create output directory
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

class DateTimeEncoder(json.JSONEncoder):
    """Helper to handle datetime objects in JSON dumps"""
    def default(self, o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        return super(DateTimeEncoder, self).default(o)

def get_account_id():
    """Fetches the current AWS Account ID."""
    return boto3.client('sts').get_caller_identity()['Account']

def get_all_regions():
    """Returns a list of all enabled regions for this account."""
    ec2 = boto3.client('ec2', region_name='us-east-1')
    try:
        response = ec2.describe_regions(AllRegions=False)
        return [r['RegionName'] for r in response['Regions']]
    except ClientError:
        return ['us-east-1']

def save_instance_detail(filename_base, full_data):
    """Saves the full data dictionary to a JSON file."""
    filename = f"{filename_base}.json"
    filepath = os.path.join(DATA_DIR, filename)
    
    try:
        with open(filepath, 'w') as f:
            json.dump(full_data, f, indent=4, cls=DateTimeEncoder)
        return filename
    except Exception as e:
        return f"Error Saving: {str(e)}"

def audit_region(region, account_id):
    """
    Worker function: Deeply audits one region.
    """
    ec2 = boto3.client('ec2', region_name=region)
    instance_rows = []
    
    try:
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    
                    # --- 1. BASIC IDENTIFIERS ---
                    inst_id = instance['InstanceId']
                    # Construct ARN: arn:aws:ec2:region:account-id:instance/instance-id
                    arn = f"arn:aws:ec2:{region}:{account_id}:instance/{inst_id}"
                    
                    # Extract Name Tag
                    inst_name = "NoName"
                    tags_formatted = []
                    if 'Tags' in instance:
                        for t in instance['Tags']:
                            tags_formatted.append(f"{t['Key']}={t['Value']}")
                            if t['Key'] == 'Name':
                                inst_name = t['Value']
                    
                    # Sanitize name for filename
                    safe_name = "".join([c if c.isalnum() else "-" for c in inst_name])
                    
                    # --- 2. DEEP DIVE: USER DATA (Startup Script) ---
                    # This requires a separate API call per instance
                    user_data_decoded = "None"
                    has_user_data = False
                    try:
                        ud_resp = ec2.describe_instance_attribute(InstanceId=inst_id, Attribute='userData')
                        if 'UserData' in ud_resp and 'Value' in ud_resp['UserData']:
                            # User data is base64 encoded
                            user_data_decoded = base64.b64decode(ud_resp['UserData']['Value']).decode('utf-8', errors='ignore')
                            has_user_data = True
                    except ClientError:
                        user_data_decoded = "AccessDenied or Error"

                    # --- 3. DEEP DIVE: STATUS CHECKS ---
                    # Checks if the system/instance is actually healthy
                    system_status = "Unknown"
                    instance_status = "Unknown"
                    try:
                        stat_resp = ec2.describe_instance_status(InstanceIds=[inst_id])
                        if stat_resp['InstanceStatuses']:
                            s = stat_resp['InstanceStatuses'][0]
                            system_status = s['SystemStatus']['Status']
                            instance_status = s['InstanceStatus']['Status']
                    except ClientError:
                        pass

                    # --- 4. DEEP DIVE: SECURITY GROUPS ---
                    # The instance object only gives IDs. We fetch the full rules here.
                    sg_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    sg_full_details = []
                    try:
                        if sg_ids:
                            sg_resp = ec2.describe_security_groups(GroupIds=sg_ids)
                            sg_full_details = sg_resp['SecurityGroups']
                    except ClientError:
                        sg_full_details = [{"Error": "Could not fetch SG Rules"}]

                    # --- 5. COMPILE FULL DATA FOR JSON ---
                    full_dump = {
                        "Metadata": {
                            "Region": region,
                            "AnalysisTime": datetime.datetime.now().isoformat(),
                            "ARN": arn
                        },
                        "Instance": instance,            # The standard AWS response
                        "Extended": {
                            "UserData": user_data_decoded,
                            "SystemStatus": system_status,
                            "InstanceStatus": instance_status,
                            "SecurityGroupsExpanded": sg_full_details
                        }
                    }
                    
                    # Save to file
                    filename = f"{region}_{safe_name}_{inst_id}"
                    file_ref = save_instance_detail(filename, full_dump)

                    # --- 6. BUILD EXCEL ROW ---
                    instance_rows.append({
                        'Instance Name': inst_name,
                        'Instance ID': inst_id,
                        'ARN': arn,
                        'Region': region,
                        'State': instance['State']['Name'],
                        'System Status': system_status,
                        'Has User Data': "YES" if has_user_data else "NO",
                        'Type': instance['InstanceType'],
                        'Public IP': instance.get('PublicIpAddress', 'N/A'),
                        'Private IP': instance.get('PrivateIpAddress', 'N/A'),
                        'VPC ID': instance.get('VpcId', 'N/A'),
                        'Subnet ID': instance.get('SubnetId', 'N/A'),
                        'IAM Profile': instance.get('IamInstanceProfile', {}).get('Arn', 'None').split('/')[-1],
                        'Key Pair': instance.get('KeyName', 'None'),
                        'Platform': instance.get('Platform', 'Linux/Unix'),
                        'Launch Time': instance['LaunchTime'].replace(tzinfo=None),
                        'Volume Count': len(instance.get('BlockDeviceMappings', [])),
                        'Full Config File': file_ref,
                        'Tags': "; ".join(tags_formatted)
                    })

    except Exception as e:
        if "AuthFailure" not in str(e):
            print(f"[{region}] Loop Error: {e}")

    return instance_rows

def main():
    start_time = time.time()
    print(f"--- AWS EC2 Ultimate Inventory Audit ---")
    print(f"1. Fetching Account Info...")
    
    try:
        account_id = get_account_id()
        print(f"   Account ID: {account_id}")
    except Exception as e:
        print(f"CRITICAL: Could not verify credentials. {e}")
        return

    print(f"2. Detecting Regions...")
    regions = get_all_regions()
    print(f"   Found {len(regions)} enabled regions.")
    
    print(f"3. Starting Deep Scan ({MAX_WORKERS} threads)...")
    print(f"   (Note: Fetching 'User Data' adds a slight delay per instance)")

    all_data = []
    regions_processed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_region = {executor.submit(audit_region, r, account_id): r for r in regions}
        
        for future in as_completed(future_to_region):
            r_name = future_to_region[future]
            regions_processed += 1
            try:
                data = future.result()
                all_data.extend(data)
                print(f"\r   Progress: {regions_processed}/{len(regions)} regions scanned. (Found {len(data)} in {r_name})", end="")
            except Exception as exc:
                print(f"\n   [{r_name}] Exception: {exc}")

    print("\n\n4. Compiling Final Report...")

    if not all_data:
        print("No instances found in any region.")
        return

    df = pd.DataFrame(all_data)

    # Sort by Region then Name
    df = df.sort_values(by=['Region', 'Instance Name'])
    
    # Organize Columns: Identifiers -> State -> Networking -> Config -> File Ref
    cols = [
        'Instance Name', 'Instance ID', 'ARN', 'Region', 'State', 'System Status', 
        'Has User Data', 'Full Config File', 'Public IP', 'Private IP', 'Type', 
        'VPC ID', 'IAM Profile', 'Launch Time'
    ]
    # Add whatever columns remain at the end
    remaining = [c for c in df.columns if c not in cols]
    df = df[cols + remaining]

    try:
        df.to_excel(OUTPUT_EXCEL, index=False)
        duration = time.time() - start_time
        print(f"✅ SUCCESS.")
        print(f"   Total Instances: {len(all_data)}")
        print(f"   Excel Summary: {OUTPUT_EXCEL}")
        print(f"   Detailed JSONs: {os.path.abspath(DATA_DIR)}")
        print(f"   Time Taken: {round(duration, 2)} seconds")
    except Exception as e:
        print(f"❌ Error saving Excel: {e}")

if __name__ == "__main__":
    main()