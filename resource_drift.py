
# resource_drift.py
#
# Generates on screen and csv reports about resource created outside CloudFormation
#
# Author: Joseph Exaltacion


from __future__ import print_function
import boto3
import argparse

def main():
    region_args = list()
    type_args = list()
    output_arg = ['txt']
    parser = argparse.ArgumentParser(description='This tool will identify resources not created by Cloudformation')
    parser.add_argument('-t','--type',nargs='*',choices=['ec2','rds','s3','elb','iam','ecs'])
    parser.add_argument('-r','--region',nargs='*')
    parser.add_argument('-o','--output',nargs=1,choices=['txt','csv'])
    try:
        for arg, values in parser.parse_args()._get_kwargs():           
            if arg == 'type' and values:
                type_args = values
            elif arg == 'type' and not values:
                type_args = ['ec2','rds','s3','elb','ecs','iam']
            elif arg =='region' and values:
                region_args = values
            elif arg =='region' and not values:
                region_args = get_regions()
            elif arg =='output' and values:
                output_arg = values
            elif arg =='output' and not values:
                output_arg = ['txt']
    except:
        pass
    if output_arg[0] == 'csv':
            print("Region,Resource_Type,Physical_Resource_ID,Resource_Metadata,Status,Notes")
    for x in type_args:
        if x !='iam' and x!= 's3':
            for region in region_args:
                cf_list = get_all_cf_resources(region)
                switcher = {
                    'ec2': [region,[{'resource_type':'AWS::AutoScaling::AutoScalingGroup','resource_list':get_running_asg_groups(region)},
                    {'resource_type':'AWS::AutoScaling::LaunchConfiguration','resource_list':get_asg_launch_configs(region)},
                    {'resource_type':'AWS::EC2::Instance','resource_list':get_running_ec2_instances(region)},
                    {'resource_type':'AWS::EC2::EIP','resource_list':get_ec2_eips(region)},
                    {'resource_type':'AWS::EC2::SecurityGroup','resource_list':get_ec2_security_groups(region)}]],
                    'rds': [region,[{'resource_type':'AWS::RDS::DBInstance', 'resource_list':get_running_rds_instances(region)}]],
                    'ecs': [region,[{'resource_type': 'AWS::ElastiCache::ReplicationGroup', 'resource_list':get_elasticache_rep_group(region)}]],
                    'elb': [region,[{'resource_type':'AWS::ElasticLoadBalancing::LoadBalancer', 'resource_list': get_elb_loadbalancers(region)},
                    {'resource_type':'AWS::ElasticLoadBalancingV2::LoadBalancer', 'resource_list':get_elbv2_loadbalancers(region)}]]
                }
                y = switcher.get(x,'nothing')
                if output_arg[0] == 'csv':
                    output_to_csv(y[0],y[1],cf_list)
                else:
                    print_to_screen(y[0],y[1],cf_list)
        elif x == 's3':
            cf_list = get_all_cf_resources("eu-west-2")
            if output_arg[0] == 'csv':
                output_to_csv('Global',[{'resource_type':'AWS::S3::Bucket', 'resource_list':get_s3_buckets()}],get_all_cf_resources("eu-west-1"))
            else:
                print_to_screen('Global',[{'resource_type':'AWS::S3::Bucket', 'resource_list':get_s3_buckets()}],get_all_cf_resources("eu-west-1"))
        elif x == 'iam':
            cf_iam_all_region_list = list()
            for region in get_regions():
                cf_list = get_all_cf_resources(region)
                for cf in cf_list:
                    if cf[1] =='AWS::IAM::Policy' or cf[1] == 'AWS::IAM::Role':
                        cf_iam_all_region_list.append(cf)
            if output_arg[0] == 'csv':
                output_to_csv('Global',[{'resource_type':'AWS::IAM::Policy','resource_list':get_iam_policies()},
                {'resource_type':'AWS::IAM::Role', 'resource_list':get_iam_roles()}],cf_iam_all_region_list)
            else:
                print_to_screen('Global',[{'resource_type':'AWS::IAM::Policy', 'resource_list':get_iam_policies()},
                {'resource_type':'AWS::IAM::Role', 'resource_list':get_iam_roles()}],cf_iam_all_region_list)
   
def get_all_cf_resources(region):
    cf_list = list([])
    cf = boto3.setup_default_session(region_name=region)
    cf = boto3.client('cloudformation')
    stack_paginator = cf.get_paginator('list_stacks')
    stack_iterator = stack_paginator.paginate(StackStatusFilter=['CREATE_IN_PROGRESS',
                         #'CREATE_FAILED',
                         'CREATE_COMPLETE',
                         #'ROLLBACK_IN_PROGRESS',
                         #'ROLLBACK_FAILED',
                         'ROLLBACK_COMPLETE',
                         #'DELETE_IN_PROGRESS',
                         'DELETE_FAILED',
                         #'DELETE_COMPLETE',
                         #'UPDATE_IN_PROGRESS',
                         #'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS',
                         'UPDATE_COMPLETE',
                         #'UPDATE_ROLLBACK_IN_PROGRESS',
                         'UPDATE_ROLLBACK_FAILED',
                         #'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS',
                         'UPDATE_ROLLBACK_COMPLETE'
                         #'REVIEW_IN_PROGRESS'
                         ])
    resource_paginator = cf.get_paginator('list_stack_resources')
    for page in stack_iterator:
        for summary in page['StackSummaries']:
            stackid = summary['StackId']
            resource_iterator = resource_paginator.paginate(StackName=stackid)
            for resource in resource_iterator:
                for resource_summary in resource['StackResourceSummaries']:
                    try:
                        cf_list.append([resource_summary['PhysicalResourceId'],resource_summary['ResourceType']])
                    except:
                        cf_list.append([resource_summary['LogicalResourceId'],resource_summary['ResourceType']])
    return cf_list

def get_running_ec2_instances(region):
    ec2 = boto3.resource('ec2',region_name=region)
    insts = list(ec2.instances.all())
    resource_list = list([])
    for inst in insts:
        for inst_tag in inst.tags:
            if inst_tag['Key'] == "Name":
                inst_name = inst_tag['Value']
        resource_list.append({'resource_id':inst.instance_id,'resource_metadata':inst_name})
    return resource_list

def get_ec2_security_groups(region):
    ec2 = boto3.resource('ec2',region_name=region)
    sgs = list(ec2.security_groups.all())
    resource_list = [{'resource_id':sg.group_id,'resource_metadata':sg.group_name} for sg in sgs]
    return resource_list

def get_running_asg_groups(region):
    asg = boto3.client('autoscaling',region_name=region)
    asg_list = asg.describe_auto_scaling_groups()
    resource_list = [{"resource_id":asgs['AutoScalingGroupName'],'resource_metadata':''} for asgs in asg_list['AutoScalingGroups']]
    return resource_list

def get_asg_instances(region):
    asg = boto3.client('autoscaling',region_name=region)
    asg_list = asg.describe_auto_scaling_instances()
    resource_list = [{'resource_id':asgs['InstanceId'],'asg_name': asgs['AutoScalingGroupName']} for asgs in asg_list['AutoScalingInstances']]
    return resource_list

def get_asg_launch_configs(region):
    asg = boto3.client('autoscaling',region_name=region)
    lconfigs = asg.describe_launch_configurations()
    resource_list = [{'resource_id':lconfig['LaunchConfigurationName'],'resource_metadata':lconfig['ImageId']} for lconfig in lconfigs['LaunchConfigurations']]
    return resource_list

def get_ec2_eips(region):
    resource_list = []
    ec2 = boto3.client('ec2',region_name=region)
    eips = ec2.describe_network_interfaces()
    for eip in eips['NetworkInterfaces']:
        try:
            resource_list.append({'resource_id':eip['NetworkInterfaceId'],'resource_metadata':eip['Attachment']['InstanceId']})
        except:
            resource_list.append({'resource_id':eip['NetworkInterfaceId'],'resource_metadata':eip['PrivateIpAddress']})
    return resource_list
     
def get_running_rds_instances(region):
    rds = boto3.client('rds',region_name=region)
    insts = rds.describe_db_instances()
    resource_list = [{'resource_id':inst['DBInstanceIdentifier'],'resource_metadata':inst['Engine']} for inst in insts['DBInstances']]
    return resource_list

def get_s3_buckets():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()
    resource_list = [{'resource_id':bucket['Name'],'resource_metadata':'' } for bucket in buckets['Buckets']]
    return resource_list

def get_bucket_location(bucketname):
    s3 = boto3.client('s3')
    location = s3.get_bucket_location(Bucket=bucketname)
    return location

def get_elb_loadbalancers(region):
    elb = boto3.client('elb',region_name=region)
    elb_list = elb.describe_load_balancers()
    resource_list = [{'resource_id':elbs['LoadBalancerName'],'resource_metadata':''} for elbs in elb_list['LoadBalancerDescriptions']]
    return resource_list

def get_elbv2_loadbalancers(region):
    elb = boto3.client('elbv2',region_name=region)
    elb_list = elb.describe_load_balancers()
    resource_list = [{'resource_id':elbs['LoadBalancerArn'],'resource_metadata':''} for elbs in elb_list['LoadBalancers']]
    return resource_list

def get_iam_roles():
    iam = boto3.client('iam')
    roles = iam.list_roles()
    resource_list = [{'resource_id':role['RoleName'],'resource_metadata':role['RoleId']} for role in roles['Roles']]
    return resource_list

def get_iam_policies():
    iam = boto3.client('iam')
    policies = iam.list_policies(Scope='Local')
    resource_list = [{'resource_id':policy['PolicyName'],'resource_metadata':policy['PolicyId']} for policy in policies['Policies']]
    return resource_list

def get_elasticache_rep_group(region):
    ecs = boto3.client('elasticache',region_name=region)
    ecs_rep_list = ecs.describe_replication_groups()
    resource_list = set([ecs_rep['ReplicationGroupId'] for ecs_rep in ecs_rep_list['ReplicationGroups']])
    return resource_list

def get_ec2_eips_instances(region):
    resource_list = []
    ec2 = boto3.client('ec2',region_name=region)
    eips = ec2.describe_network_interfaces()
    for eip in eips['NetworkInterfaces']:
        try:
            resource_list.append({'eip_instance': eip['Attachment']['InstanceId'],'eip_netinterface':eip['NetworkInterfaceId']})
        except:
            resource_list.append({'eip_instance': eip['Description'],'eip_netinterface':eip['NetworkInterfaceId']})
    return resource_list

def get_regions():
    # BUG: We could potentially end up with > 1 request worth of regions returned
    try:
        import botocore.exceptions
        ec2 = boto3.client('ec2')
    except botocore.exceptions.NoRegionError:
        # If we fail because the user has no default region, use us-east-1
        # This is for listing regions only
        # Iterating stacks and resources is then performed across all regions
        ec2 = boto3.client('ec2', region_name='us-east-1')
    regions = ec2.describe_regions()['Regions']
    region_names = set([region['RegionName'] for region in regions])
    return region_names

def print_ec2_instances(drift_set,instance_list,region):
    asg_inst_list = get_asg_instances(region)
    asg_inst_set = set([asg_inst['resource_id'] for asg_inst in asg_inst_list])
    asg_instance_count = 0
    #if len(asg_inst_set) > 0:
    for current_ec2_inst in instance_list:
        if current_ec2_inst['resource_id'] in asg_inst_set and current_ec2_inst['resource_id'] in drift_set:
            for current_asg_inst in asg_inst_list:
                if current_ec2_inst['resource_id'] == current_asg_inst['resource_id']:
                    print ("-",current_ec2_inst['resource_id']," ",current_ec2_inst['resource_metadata'], "  (No Drift - created by ASG", current_asg_inst['asg_name'],")\n")
                    asg_instance_count +=1
        elif current_ec2_inst['resource_id'] in drift_set:
                print ("-",current_ec2_inst['resource_id']," ", current_ec2_inst['resource_metadata'], "\n")
    return asg_instance_count

def print_ec2_instances_csv(drift_set,instance_list,region):
    asg_inst_list = get_asg_instances(region)
    asg_inst_set = set([asg_inst['resource_id'] for asg_inst in asg_inst_list])
    asg_instance_count = 0
    #if len(asg_inst_set) > 0:
    for current_ec2_inst in instance_list:
        if current_ec2_inst['resource_id'] in asg_inst_set and current_ec2_inst['resource_id'] in drift_set:
            for current_asg_inst in asg_inst_list:
                if current_ec2_inst['resource_id'] == current_asg_inst['resource_id']:
                    print('\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"'.format(region,"AWS::EC2::Instance",current_ec2_inst['resource_id'],current_ec2_inst['resource_metadata'],"SYNC","Part of AutoScaling Group " + current_asg_inst['asg_name']))
        elif current_ec2_inst['resource_id'] in drift_set:
            print('\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"'.format(region,"AWS::EC2::Instance",current_ec2_inst['resource_id'],current_ec2_inst['resource_metadata'],"DRIFT",""))
        else:
            print('\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"'.format(region,"AWS::EC2::Instance",current_ec2_inst['resource_id'],current_ec2_inst['resource_metadata'],"SYNC",""))

def print_eips(drift_set,eip_list,region):
    asg_inst_list = get_asg_instances(region)
    asg_inst_set = set([asg_inst['resource_id'] for asg_inst in asg_inst_list])
    eip_list = get_ec2_eips_instances(region)
    asg_instance_count = 0
    for current_eip in eip_list:
        if current_eip['eip_instance'] in asg_inst_set and current_eip['eip_netinterface'] in drift_set:
            for current_asg_inst in asg_inst_list:
                if current_eip['eip_instance'] == current_asg_inst['resource_id']:
                    print ("-",current_eip['eip_netinterface']," ",current_eip['eip_instance'], "  (No Drift - created by ASG", current_asg_inst['asg_name'],")\n")
                    asg_instance_count +=1
        elif current_eip['eip_netinterface'] in drift_set:
                print ("-",current_eip['eip_netinterface']," ", current_eip['eip_instance'], "\n")
    return asg_instance_count

def print_eips_csv(drift_set,eip_list,region):
    asg_inst_list = get_asg_instances(region)
    asg_inst_set = set([asg_inst['resource_id'] for asg_inst in asg_inst_list])
    eip_list = get_ec2_eips_instances(region)
    asg_instance_count = 0
    for current_eip in eip_list:
        if current_eip['eip_instance'] in asg_inst_set and current_eip['eip_netinterface'] in drift_set:
            for current_asg_inst in asg_inst_list:
                if current_eip['eip_instance'] == current_asg_inst['resource_id']:
                    print('\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"'.format(region,"AWS::EC2::EIP",current_eip['eip_netinterface'],"SYNC",("EIP attached to ASG instance " + current_eip['eip_instance'])))
        elif current_eip['eip_netinterface'] in drift_set:
            print('\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"'.format(region,"AWS::EC2::EIP",current_eip['eip_netinterface'],current_eip['eip_instance'],"DRIFT",""))
        else:
            print('\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"'.format(region,"AWS::EC2::EIP",current_eip['eip_netinterface'],current_eip['eip_instance'],"SYNC",""))
    return asg_instance_count

def print_s3_buckets(drift_set,bucket_list,region):
    for current in bucket_list:
        try:
            location = get_bucket_location(current['resource_id'])
        except:
            location = {'LocationConstraint':'Unable to get Region'}
        if current['resource_id'] in drift_set:
            print("-",current['resource_id'],"  (Region:", location['LocationConstraint'],")\n")

def print_s3_buckets_csv(drift_set,bucket_list,region):
    for current in bucket_list:
        try:
            location = get_bucket_location(current['resource_id'])
        except:
            location = {'LocationConstraint':'Unable to get Region'}
        if current['resource_id'] in drift_set:
             print('\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"'.format(region,'AWS::S3::Bucket',current['resource_id'],location['LocationConstraint'],"DRIFT",""))
        else:
            print('\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"'.format(region,'AWS::S3::Bucket',current['resource_id'],location['LocationConstraint'],"SYNC",""))

def print_to_screen(region,running_resource_list,cf_list):
    for running_resource in running_resource_list:
        asg_count = 0
        resource_list = running_resource['resource_list']
        resource_type = running_resource['resource_type']
        resource_set = set([resource['resource_id'] for resource in resource_list])
        temp = resource_type.rsplit(':',1)
        resource_name = temp[1]
        heading = "-- Region: " + region + "    Resource: " + resource_type + " --"
        print ("-" * len(heading))
        print (heading)
        print ("-" * len(heading))
        filtered_cf_set = set([x[0] for x in cf_list if x[1]==resource_type])
        drift_set = resource_set - filtered_cf_set
        drift_count = len(drift_set) 
        if drift_count > 0:
            print (resource_name,"s created outside CloudFormation: \n", sep='')
            if resource_type == 'AWS::EC2::Instance':
                asg_count = print_ec2_instances(drift_set,resource_list,region)
            elif resource_type == 'AWS::EC2::EIP':
                asg_count = print_eips(drift_set,resource_list,region)
            elif resource_type =='AWS::S3::Bucket':
                print_s3_buckets(drift_set,resource_list,region) 
            else:
                for current in resource_list:
                    if current['resource_id'] in drift_set: 
                        print ("-",current['resource_id']," ",current['resource_metadata'], "\n")
            print ("Summary")
            print ("Total ",resource_name,"s created in CloudFormation: ", len(filtered_cf_set), sep='')
            print ("Total running ",resource_name, "s found: ", len(resource_set),sep='')
            if asg_count > 0:
                print ("Total ",resource_name, "s associated with an ASG: ", asg_count, sep='')
                print ("Total ",resource_name, "s with config drift: ", drift_count-asg_count, " (", round(((float(drift_count)-asg_count)/len(resource_set))*100,2), "%)",sep='')
            else:
                print ("Total ",resource_name, "s with config drift: ", len(drift_set), " (", round((float(len(drift_set))/len(resource_set))*100,2), "%)",sep='')
            print ("\n")
        else:
            print ("Summary")
            print ("Total ",resource_name,"s created in CloudFormation: ", len(filtered_cf_set), sep='')
            print ("Total ",resource_name, "s found: ", len(resource_set),sep='')
            print ("Total ",resource_name, "s with config drift: ", len(drift_set), sep='')
            print ("\n")
    
def output_to_csv(region,running_resource_list,cf_list):
    for running_resource in running_resource_list:
        resource_list = running_resource['resource_list']
        resource_set = set([resource['resource_id'] for resource in resource_list])
        resource_type = running_resource['resource_type']
        filtered_cf_set = set([x[0] for x in cf_list if x[1]==resource_type])
        drift_set = resource_set - filtered_cf_set
        if len(drift_set) > 0:
            if resource_type =='AWS::EC2::Instance':
                print_ec2_instances_csv(drift_set,resource_list,region)
            elif resource_type =='AWS::EC2::EIP':
                print_eips_csv(drift_set,resource_list,region)
            elif resource_type =='AWS::S3::Bucket':
                print_s3_buckets_csv(drift_set,resource_list,region) 
            else:
                for current in resource_list:
                    if current['resource_id'] in filtered_cf_set:
                        print('\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"'.format(region,resource_type,current['resource_id'],current['resource_metadata'],"SYNC",""))
                    else:
                        print('\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"'.format(region,resource_type,current['resource_id'],current['resource_metadata'],"DRIFT",""))
        else:
            for current in resource_list:
                print('\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"'.format(region,resource_type,current['resource_id'],current['resource_metadata'],"SYNC",""))
        
if __name__ == '__main__':
    main()



















