import boto3
import pandas as pd
import json
import os
import datetime
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# --- CONFIGURATION ---
OUTPUT_FILE = "aws_network_master_audit.xlsx"
MAX_WORKERS = 20

# Folders for raw details
DIR_VPC = "details_vpc"
DIR_SG = "details_sg"
DIR_NACL = "details_nacl"

for d in [DIR_VPC, DIR_SG, DIR_NACL]:
    if not os.path.exists(d):
        os.makedirs(d)

# --- HELPERS ---

class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        return super(DateTimeEncoder, self).default(o)

def save_raw_json(folder, filename, data):
    """Saves full attribute dump to JSON"""
    path = os.path.join(folder, filename)
    with open(path, 'w') as f:
        json.dump(data, f, indent=4, cls=DateTimeEncoder)
    return filename

def get_tag_value(tags, key):
    if not tags: return ""
    for t in tags:
        if t['Key'] == key:
            return t['Value']
    return ""

def format_sg_rules(permissions):
    """Formats complex SG rules into a readable text block."""
    lines = []
    for p in permissions:
        proto = p.get('IpProtocol', 'All')
        if proto == '-1': proto = 'ALL TRAFFIC'
        
        # Ports
        from_p = p.get('FromPort', 'All')
        to_p = p.get('ToPort', 'All')
        port_str = f"{from_p}" if from_p == to_p else f"{from_p}-{to_p}"
        if from_p == 'All': port_str = "ALL"

        # Sources
        sources = []
        for ip in p.get('IpRanges', []):
            desc = f" ({ip['Description']})" if 'Description' in ip else ""
            sources.append(f"{ip['CidrIp']}{desc}")
        for ip6 in p.get('Ipv6Ranges', []):
            desc = f" ({ip6['Description']})" if 'Description' in ip6 else ""
            sources.append(f"{ip6['CidrIpv6']}{desc}")
        for uid in p.get('UserIdGroupPairs', []):
            sources.append(f"SG:{uid.get('GroupId')}")
        for pl in p.get('PrefixListIds', []):
            sources.append(f"PL:{pl.get('PrefixListId')}")

        if not sources: sources = ["0.0.0.0/0 (Implied)"]
        
        lines.append(f"[{proto.upper()} Port:{port_str}] allowed from: {', '.join(sources)}")
    
    return "\n".join(lines)

def format_nacl_rules(entries):
    """Formats NACL rules, sorted by rule number."""
    sorted_entries = sorted(entries, key=lambda x: x['RuleNumber'])
    lines = []
    for e in sorted_entries:
        action = "ALLOW" if e['RuleAction'] == 'allow' else "DENY"
        num = e['RuleNumber']
        cidr = e.get('CidrBlock', e.get('Ipv6CidrBlock', 'N/A'))
        
        proto = e.get('Protocol', 'All')
        if proto == '-1': proto = 'ALL'
        elif proto == '6': proto = 'TCP'
        elif proto == '17': proto = 'UDP'
        elif proto == '1': proto = 'ICMP'

        port = "ALL"
        if 'PortRange' in e:
            if e['PortRange']['From'] == e['PortRange']['To']:
                port = str(e['PortRange']['From'])
            else:
                port = f"{e['PortRange']['From']}-{e['PortRange']['To']}"
        
        lines.append(f"#{num} {action} | {proto} Port:{port} | Source:{cidr}")
    return "\n".join(lines)

# --- WORKER ---

def audit_region(region, account_id):
    ec2 = boto3.client('ec2', region_name=region)
    
    res_vpc = []
    res_sg = []
    res_nacl = []
    
    try:
        # 1. VPC AUDIT
        vpcs = ec2.describe_vpcs()['Vpcs']
        for v in vpcs:
            vpc_id = v['VpcId']
            name = get_tag_value(v.get('Tags'), 'Name')
            arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"
            
            # Handle IPv6
            ipv6_blocks = [b['Ipv6CidrBlock'] for b in v.get('Ipv6CidrBlockAssociationSet', [])]
            
            # Save Full Detail
            file_ref = save_raw_json(DIR_VPC, f"{region}_{vpc_id}.json", v)

            res_vpc.append({
                'Name': name,
                'VPC ID': vpc_id,
                'ARN': arn,
                'Region': region,
                'CIDR (IPv4)': v['CidrBlock'],
                'IPv6 Blocks': ", ".join(ipv6_blocks),
                'State': v['State'],
                'Is Default': v['IsDefault'],
                'Instance Tenancy': v['InstanceTenancy'],
                'DHCP Options ID': v.get('DhcpOptionsId', 'N/A'),
                'Owner ID': v['OwnerId'],
                'Full Detail File': file_ref
            })

        # 2. SECURITY GROUP AUDIT
        paginator = ec2.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                sg_id = sg['GroupId']
                name = sg['GroupName']
                arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"
                
                in_rules = format_sg_rules(sg.get('IpPermissions', []))
                out_rules = format_sg_rules(sg.get('IpPermissionsEgress', []))
                
                file_ref = save_raw_json(DIR_SG, f"{region}_{sg_id}.json", sg)

                res_sg.append({
                    'Group Name': name,
                    'Group ID': sg_id,
                    'ARN': arn,
                    'Region': region,
                    'VPC ID': sg.get('VpcId'),
                    'Description': sg.get('Description'),
                    'Inbound Rule Count': len(sg.get('IpPermissions', [])),
                    'Outbound Rule Count': len(sg.get('IpPermissionsEgress', [])),
                    'Inbound Rules Summary': in_rules,
                    'Outbound Rules Summary': out_rules,
                    'Full Detail File': file_ref
                })

        # 3. NACL AUDIT
        nacls = ec2.describe_network_acls()['NetworkAcls']
        for acl in nacls:
            acl_id = acl['NetworkAclId']
            name = get_tag_value(acl.get('Tags'), 'Name')
            arn = f"arn:aws:ec2:{region}:{account_id}:network-acl/{acl_id}"
            
            subnets = [a['SubnetId'] for a in acl['Associations']]
            
            # Split Inbound/Outbound
            entries_in = [e for e in acl['Entries'] if not e['Egress']]
            entries_out = [e for e in acl['Entries'] if e['Egress']]
            
            file_ref = save_raw_json(DIR_NACL, f"{region}_{acl_id}.json", acl)

            res_nacl.append({
                'NACL Name': name,
                'NACL ID': acl_id,
                'ARN': arn,
                'Region': region,
                'VPC ID': acl['VpcId'],
                'Is Default': acl['IsDefault'],
                'Associated Subnets Count': len(subnets),
                'Associated Subnet IDs': ", ".join(subnets),
                'Inbound Rules': format_nacl_rules(entries_in),
                'Outbound Rules': format_nacl_rules(entries_out),
                'Full Detail File': file_ref
            })

    except Exception as e:
        # Silently fail on regions we can't access, or print if critical
        if "AuthFailure" not in str(e):
            print(f"[{region}] Partial Error: {e}")

    return res_vpc, res_sg, res_nacl

# --- MAIN ---

def main():
    start_time = time.time()
    print("--- AWS Master Network Audit (VPC + SG + NACL) ---")
    print(f"Output Excel: {OUTPUT_FILE}")
    print(f"Detail Folders: ./{DIR_VPC}/, ./{DIR_SG}/, ./{DIR_NACL}/")

    # Get Account ID
    try:
        account_id = boto3.client('sts').get_caller_identity()['Account']
    except Exception as e:
        print(f"Critical Error: {e}")
        return

    # Get Regions
    ec2 = boto3.client('ec2', region_name='us-east-1')
    regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
    
    print(f"Scanning {len(regions)} regions with {MAX_WORKERS} threads...")

    # Parallel Scan
    all_vpc, all_sg, all_nacl = [], [], []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(audit_region, r, account_id): r for r in regions}
        
        done = 0
        for future in as_completed(future_map):
            done += 1
            r_name = future_map[future]
            print(f"\rProgress: {done}/{len(regions)} ({r_name})", end="")
            
            v, s, n = future.result()
            all_vpc.extend(v)
            all_sg.extend(s)
            all_nacl.extend(n)

    print("\n\nCompiling Excel Report...")

    # Create DataFrames
    df_vpc = pd.DataFrame(all_vpc)
    df_sg = pd.DataFrame(all_sg)
    df_nacl = pd.DataFrame(all_nacl)

    # ORDER COLUMNS
    if not df_vpc.empty:
        cols = ['Name', 'VPC ID', 'ARN', 'Region', 'CIDR (IPv4)', 'Full Detail File', 'State']
        rem = [c for c in df_vpc.columns if c not in cols]
        df_vpc = df_vpc[cols + rem]
        
    if not df_sg.empty:
        cols = ['Group Name', 'Group ID', 'ARN', 'Region', 'VPC ID', 'Full Detail File', 'Inbound Rule Count', 'Inbound Rules Summary']
        rem = [c for c in df_sg.columns if c not in cols]
        df_sg = df_sg[cols + rem]
        
    if not df_nacl.empty:
        cols = ['NACL Name', 'NACL ID', 'ARN', 'Region', 'VPC ID', 'Full Detail File', 'Associated Subnets Count', 'Inbound Rules']
        rem = [c for c in df_nacl.columns if c not in cols]
        df_nacl = df_nacl[cols + rem]

    # Write to Excel
    try:
        with pd.ExcelWriter(OUTPUT_FILE, engine='openpyxl') as writer:
            df_vpc.to_excel(writer, sheet_name='VPCs', index=False)
            df_sg.to_excel(writer, sheet_name='Security Groups', index=False)
            df_nacl.to_excel(writer, sheet_name='NACLs', index=False)
            
        print("✅ DONE.")
        print(f"   - VPCs Found: {len(all_vpc)}")
        print(f"   - Security Groups Found: {len(all_sg)}")
        print(f"   - NACLs Found: {len(all_nacl)}")
        print(f"   - Time: {round(time.time() - start_time, 2)}s")
    except Exception as e:
        print(f"❌ Error writing Excel: {e}")

if __name__ == "__main__":
    main()