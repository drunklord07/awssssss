import boto3
import pandas as pd
import json
import os
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# --- CONFIGURATION ---
OUTPUT_EXCEL = "s3_inventory_index.xlsx"
POLICY_DIR = "s3_bucket_policies"
MAX_WORKERS = 50 

# Create the policy directory if it doesn't exist
if not os.path.exists(POLICY_DIR):
    os.makedirs(POLICY_DIR)

def format_err(api_name, e):
    """Returns strict Error Code to avoid leaking Account IDs."""
    error_code = e.response.get('Error', {}).get('Code', 'UnknownError')
    return f"[{api_name}] {error_code}"

def save_policy_to_file(bucket_name, policy_text):
    """Saves the policy string to a formatted JSON file."""
    filename = f"{bucket_name}.json"
    filepath = os.path.join(POLICY_DIR, filename)
    
    try:
        policy_json = json.loads(policy_text)
        with open(filepath, 'w') as f:
            json.dump(policy_json, f, indent=4)
        return filename
    except Exception as e:
        return f"Error Saving File: {str(e)}"

def get_bucket_data(bucket_name, creation_date):
    """
    Worker function that queries ONE bucket for ALL attributes.
    """
    s3_generic = boto3.client('s3')
    
    # --- CONSTRUCT S3 ARN ---
    # Standard format: arn:aws:s3:::bucket_name
    # (Note: S3 ARNs generally do not include Region or Account ID)
    arn = f"arn:aws:s3:::{bucket_name}"

    data = {
        'Bucket Name': bucket_name,
        'ARN': arn,  # <--- ADDED ARN HERE
        'Creation Date': creation_date.replace(tzinfo=None)
    }

    # 1. Determine Region
    try:
        loc_resp = s3_generic.get_bucket_location(Bucket=bucket_name)
        region = loc_resp['LocationConstraint']
        if region is None: region = 'us-east-1'
        data['Region'] = region
    except ClientError as e:
        data['Region'] = 'us-east-1' 
        data['Meta Error'] = format_err('GetBucketLocation', e)
        region = 'us-east-1'

    s3 = boto3.client('s3', region_name=region)

    # --- 2. BUCKET POLICY (Save to File) ---
    try:
        pol_resp = s3.get_bucket_policy(Bucket=bucket_name)
        filename = save_policy_to_file(bucket_name, pol_resp['Policy'])
        data['Policy File'] = filename
    except ClientError as e:
        if 'NoSuchBucketPolicy' in e.response['Error']['Code']:
            data['Policy File'] = "No Policy"
        else:
            data['Policy File'] = format_err('GetBucketPolicy', e)

    # --- 3. Public Access Block ---
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        conf = pab['PublicAccessBlockConfiguration']
        data['Public Access Block'] = f"BlockACLs:{conf['BlockPublicAcls']}, BlockPolicy:{conf['BlockPublicPolicy']}"
    except ClientError as e:
        if 'NoSuchPublicAccessBlock' in e.response['Error']['Code']:
            data['Public Access Block'] = "Not Configured (Potentially Public)"
        else:
            data['Public Access Block'] = format_err('GetPublicAccessBlock', e)

    # --- 4. Encryption ---
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']
        data['Encryption'] = f"{rules.get('SSEAlgorithm')}"
    except ClientError as e:
        if 'ServerSideEncryptionConfigurationNotFoundError' in e.response['Error']['Code']:
            data['Encryption'] = "Not Encrypted"
        else:
            data['Encryption'] = format_err('GetBucketEncryption', e)

    # --- 5. Object Lock ---
    try:
        lock = s3.get_object_lock_configuration(Bucket=bucket_name)
        data['Object Lock'] = lock['ObjectLockConfiguration']['ObjectLockEnabled']
    except ClientError as e:
        if 'ObjectLockConfigurationNotFoundError' in e.response['Error']['Code']:
            data['Object Lock'] = "Disabled"
        else:
            data['Object Lock'] = format_err('GetObjectLock', e)

    # --- 6. Versioning ---
    try:
        ver = s3.get_bucket_versioning(Bucket=bucket_name)
        data['Versioning'] = ver.get('Status', 'Disabled')
    except ClientError as e:
        data['Versioning'] = format_err('GetBucketVersioning', e)

    # --- 7. Lifecycle Rules ---
    try:
        life = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        data['Lifecycle Rules'] = f"{len(life['Rules'])} Rules"
    except ClientError as e:
        if 'NoSuchLifecycleConfiguration' in e.response['Error']['Code']:
            data['Lifecycle Rules'] = "None"
        else:
            data['Lifecycle Rules'] = format_err('GetLifecycle', e)

    # --- 8. Logging ---
    try:
        log = s3.get_bucket_logging(Bucket=bucket_name)
        if 'LoggingEnabled' in log:
            data['Logging'] = f"Target: {log['LoggingEnabled']['TargetBucket']}"
        else:
            data['Logging'] = "Disabled"
    except ClientError as e:
        data['Logging'] = format_err('GetBucketLogging', e)

    # --- 9. Tags ---
    try:
        tags = s3.get_bucket_tagging(Bucket=bucket_name)
        tag_list = [f"{t['Key']}={t['Value']}" for t in tags['TagSet']]
        data['Tags'] = "; ".join(tag_list)
    except ClientError as e:
        if 'NoSuchTagSet' in e.response['Error']['Code']:
            data['Tags'] = "No Tags"
        else:
            data['Tags'] = format_err('GetBucketTagging', e)

    # --- 10. Static Website ---
    try:
        web = s3.get_bucket_website(Bucket=bucket_name)
        data['Website Hosting'] = "Enabled"
    except ClientError as e:
        if 'NoSuchWebsiteConfiguration' in e.response['Error']['Code']:
            data['Website Hosting'] = "Disabled"
        else:
            data['Website Hosting'] = format_err('GetBucketWebsite', e)

    return data

def main():
    start_time = time.time()
    print(f"--- AWS S3 Audit (With ARN) ---")
    print(f"Policies folder: ./{POLICY_DIR}/")
    
    s3 = boto3.client('s3')
    
    print("1. Listing Buckets...")
    try:
        buckets_raw = s3.list_buckets()
        buckets = buckets_raw['Buckets']
        total = len(buckets)
        print(f"   Found {total} buckets.")
    except Exception as e:
        print(f"CRITICAL ERROR: Could not list buckets. {e}")
        return

    results = []
    processed = 0

    print(f"2. Starting Parallel Audit ({MAX_WORKERS} threads)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_bucket = {executor.submit(get_bucket_data, b['Name'], b['CreationDate']): b for b in buckets}
        
        for future in as_completed(future_to_bucket):
            processed += 1
            try:
                data = future.result()
                results.append(data)
                print(f"\r   Progress: {processed}/{total} ({data['Bucket Name']})", end="")
            except Exception as exc:
                print(f"\n   Exception in thread: {exc}")

    print("\n\n3. Compiling Excel file...")
    df = pd.DataFrame(results)
    
    # Reorder columns: ARN is now the 2nd column
    first_cols = ['Bucket Name', 'ARN', 'Region', 'Policy File', 'Public Access Block', 'Encryption', 'Versioning']
    remaining_cols = [c for c in df.columns if c not in first_cols]
    df = df[first_cols + remaining_cols]
    
    try:
        df.to_excel(OUTPUT_EXCEL, index=False)
        duration = time.time() - start_time
        print(f"✅ SUCCESS.")
        print(f"   Excel Report: {OUTPUT_EXCEL}")
        print(f"   Policy Files: {os.path.abspath(POLICY_DIR)}")
        print(f"   Time taken: {round(duration, 2)} seconds")
    except Exception as e:
        print(f"❌ Error saving Excel: {e}")

if __name__ == "__main__":
    main()