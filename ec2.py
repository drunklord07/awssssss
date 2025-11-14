import boto3
import pandas as pd
import json
import os
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import datetime

# --- CONFIGURATION ---
OUTPUT_EXCEL = "ec2_inventory_index.xlsx"
DATA_DIR = "ec2_instance_details"
MAX_WORKERS = 20 

# Create output directory
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

class DateTimeEncoder(json.JSONEncoder):
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
    except ClientError as e:
        print(f"Error fetching regions: {e}")
        return ['us-east-1']

def save_instance_detail(instance_data, sg_rules, region, arn):
    """
    Saves the full raw JSON of the instance + SG Rules to a file.
    """
    instance_id = instance_data['InstanceId']
    
    # Extract Name tag for filename
    name = "NoName"
    if 'Tags' in instance_data:
        for tag in instance_data['Tags']:
            if tag['Key'] == 'Name':
                name = tag['Value'].replace('/', '-')
                break
    
    filename = f"{region}_{name}_{instance_id}.json"
    filepath = os.path.join(DATA_DIR, filename)
    
    full_dump = {
        "AnalysisTimestamp": datetime.datetime.now().isoformat(),
        "Region": region,
        "ARN": arn,  # <--- Added ARN to JSON
        "InstanceDetails": instance_data,
        "SecurityGroupRules": sg_rules
    }

    try:
        with open(filepath, 'w') as f:
            json.dump(full_dump, f, indent=4, cls=DateTimeEncoder)
        return filename
    except Exception:
        return "Error Saving File"

def audit_region(region, account_id):
    """
    Worker function: Connects to a specific region and gathers all instances.
    """
    ec2 = boto3.client('ec2', region_name=region)
    instance_list = []
    
    try:
        paginator = ec2.get_paginator('describe_instances')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    
                    # 1. Basic Identifiers
                    inst_id = instance['InstanceId']
                    
                    # --- CONSTRUCT ARN ---
                    # Format: arn:aws:ec2:region:account-id:instance/instance-id
                    arn = f"arn:aws:ec2:{region}:{account_id}:instance/{inst_id}"
                    
                    inst_type = instance['InstanceType']
                    state = instance['State']['Name']
                    launch_time = instance['LaunchTime'].replace(tzinfo=None)
                    
                    # 2. Extract "Name" Tag
                    inst_name = ""
                    tags_formatted = ""
                    if 'Tags' in instance:
                        tags_formatted = "; ".join([f"{t['Key']}={t['Value']}" for t in instance['Tags']])
                        for tag in instance['Tags']:
                            if tag['Key'] == 'Name':
                                inst_name = tag['Value']
                    
                    # 3. Network
                    pub_ip = instance.get('PublicIpAddress', 'N/A')
                    priv_ip = instance.get('PrivateIpAddress', 'N/A')
                    vpc_id = instance.get('VpcId', 'N/A')
                    subnet_id = instance.get('SubnetId', 'N/A')

                    # 4. Fetch Security Group Rules
                    sg_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    sg_details = []
                    try:
                        if sg_ids:
                            sg_resp = ec2.describe_security_groups(GroupIds=sg_ids)
                            sg_details = sg_resp['SecurityGroups']
                    except ClientError:
                        sg_details = [{"Error": "Could not fetch Security Group Rules"}]

                    # 5. IAM Profile
                    iam_profile = "None"
                    if 'IamInstanceProfile' in instance:
                        iam_profile = instance['IamInstanceProfile']['Arn'].split('/')[-1]

                    # 6. Storage
                    root_device = instance.get('RootDeviceName', 'N/A')
                    vol_count = len(instance.get('BlockDeviceMappings', []))

                    # 7. Save Full Details (Passing ARN now)
                    json_file = save_instance_detail(instance, sg_details, region, arn)

                    # 8. Build Row for Excel
                    instance_list.append({
                        'Instance Name': inst_name,
                        'Instance ID': inst_id,
                        'ARN': arn,  # <--- Added ARN Column
                        'Region': region,
                        'State': state,
                        'Type': inst_type,
                        'Public IP': pub_ip,
                        'Private IP': priv_ip,
                        'VPC ID': vpc_id,
                        'Subnet ID': subnet_id,
                        'IAM Profile': iam_profile,
                        'Key Pair': instance.get('KeyName', 'None'),
                        'Launch Time': launch_time,
                        'Platform': instance.get('Platform', 'Linux/Unix'),
                        'Root Device': root_device,
                        'Volume Count': vol_count,
                        'Full Config File': json_file,
                        'Tags': tags_formatted
                    })

    except ClientError as e:
        if "AuthFailure" in str(e) or "OptInRequired" in str(e):
            pass
        else:
            print(f"[{region}] Error: {e}")

    return instance_list

def main():
    start_time = time.time()
    print(f"--- AWS EC2 Global Audit (With ARN) ---")
    
    # 1. Get Account ID
    try:
        account_id = get_account_id()
        print(f"1. Account ID: {account_id}")
    except Exception as e:
        print(f"CRITICAL ERROR: Could not get Account ID. {e}")
        return

    # 2. Get Regions
    print("2. Detecting enabled regions...")
    regions = get_all_regions()
    print(f"   Found {len(regions)} regions. Starting parallel scan...")

    all_instances = []
    processed_regions = 0

    # 3. Parallel Processing
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Pass Account ID to the worker function
        future_to_region = {executor.submit(audit_region, r, account_id): r for r in regions}
        
        for future in as_completed(future_to_region):
            region_name = future_to_region[future]
            processed_regions += 1
            try:
                data = future.result()
                all_instances.extend(data)
                count = len(data)
                print(f"\r   Progress: Scanned {processed_regions}/{len(regions)} regions. (Found {count} in {region_name})", end="")
            except Exception as exc:
                print(f"\n   [{region_name}] generated an exception: {exc}")

    print("\n\n4. Compiling Excel file...")
    
    if not all_instances:
        print("No instances found in any region.")
        return

    df = pd.DataFrame(all_instances)

    # Sort and Reorder
    df = df.sort_values(by=['Region', 'Instance Name'])
    
    # Updated Column Order to include ARN Prominently
    cols = ['Instance Name', 'Instance ID', 'ARN', 'Region', 'State', 'Full Config File', 'Public IP', 'Type']
    remaining = [c for c in df.columns if c not in cols]
    df = df[cols + remaining]

    try:
        df.to_excel(OUTPUT_EXCEL, index=False)
        duration = time.time() - start_time
        print(f"✅ SUCCESS. Found {len(all_instances)} instances.")
        print(f"   Excel Summary: {OUTPUT_EXCEL}")
        print(f"   Detailed JSONs: {os.path.abspath(DATA_DIR)}")
        print(f"   Time taken: {round(duration, 2)} seconds")
    except Exception as e:
        print(f"❌ Error saving Excel: {e}")

if __name__ == "__main__":
    main()