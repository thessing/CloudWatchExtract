#
# CloudWatchExtract (CWE) Lambda - lambda_function.py
#
# Description:- This will extract CloudWatch LogGroups (listed in DynamoDB) and store them in a S3 bucket (also in S3)
#
# Author: Tim Hessing
# Created: 07-12-2022
# Updated: 07-13-2022
#
import json
import boto3
import time

#
# Create Boto3 Clients
dynamo_client  = boto3.client('dynamodb')
log_client     = boto3.client('logs')
ssm_client     = boto3.client('ssm')

def lambda_handler(event, context):
    #
    # Get Information from DynamoDB
    # Make sure Main Table Exists
    try:
        descrTable = dynamo_client.describe_table(TableName='CWEMainTable')
        print("Main CWE Table Exists ", descrTable)
    except:
        print("ERROR: No CWEMainTable")
        return
    #
    # Now see if anything is in it or too many things in it (if not return)
    try:
        scanResponse = dynamo_client.scan(TableName='CWEMainTable', Select='ALL_ATTRIBUTES')
        print("Scan succeeded ", scanResponse)
    except:
        print("ERROR: CWEMainTable Scan Failed!!!")
        return 
    #
    # If count zero then return bad
    print("Count: ", scanResponse['Count'] )
    if scanResponse['Count'] == 0:
        print("ERROR: No items!!! Count=", scanResponse['Count'])
        return 
    #
    # Verify 1 item only
    if scanResponse['Count'] != 1:
        print("ERROR: Too many items!!! Count=", scanResponse['Count'])
        return
    #
    # Extract Defaults
    LogBucket = scanResponse['Items'][0]['data-bucket']['S']
    print("Log Bucket is ", LogBucket)
 
    #
    # Make sure Log Table Exists
    try:
        descrTable = dynamo_client.describe_table(TableName='CWELogTable')
        print("CWE Log Table Exists ", descrTable)
    except:
        print("ERROR: No CWELogTable")
        return
    #
    # Now see if anything is in it or too many things in it (if not return)
    try:
        scanResponse = dynamo_client.scan(TableName='CWELogTable', Select='ALL_ATTRIBUTES')
        print("Scan succeeded ", scanResponse)
    except:
        print("ERROR: CWELogTable Scan Failed!!!")
        return 
    #
    # If count zero then return bad
    print("Count: ", scanResponse['Count'] )
    if scanResponse['Count'] == 0:
        print("ERROR: No items!!! Count=", scanResponse['Count'])
        return 
    #
    # Extract List of LogGroups
    LogGroupList = []
    for item in scanResponse['Items']:
        lg = item['log-group']['S']
        LogGroupList.append(lg)
    print("The list of LogGroups is ", LogGroupList)
    #
    # If we have a LogGroup to Extract let's do it
    for logGroup in LogGroupList:
        ssmParameterName = ("/logs-exporter-last-export/%s" % logGroup).replace("//", "/")
        try:
            ssmResponse = ssm_client.get_parameter(Name=ssmParameterName)
            ssmValue    = ssmResponse['Parameter']['Value']
        except ssm_client.exceptions.ParameterNotFound:
            ssmValue = "0"
        
        export2time = int(round(time.time() * 1000))
        
        print("--> Exporting %s to %s" % (logGroup, LogBucket))
        
        if export2time - int(ssmValue) < (24 * 60 * 60 * 1000):
            # Haven't been 24hrs from the last export of this log group
            print("    Skipped until 24hrs from last export is completed")
            continue
        
        try:
            dprefix = logGroup
            if logGroup[0] == '/':
                dprefix = logGroup[1:]

            response = log_client.create_export_task(
                logGroupName=logGroup,
                fromTime=int(ssmValue),
                to=export2time,
                destination=LogBucket,
                destinationPrefix=dprefix )
            print("    Task created: %s" % response['taskId'])
            time.sleep(5)
            
        except log_client.exceptions.LimitExceededException:
            print("    Need to wait until all tasks are finished (LimitExceededException). Continuing later...")
            return
        
        except Exception as e:
            print("    Error exporting %s: %s" % (logGroup, getattr(e, 'message', repr(e))))
            continue
        
        ssm_response = ssm_client.put_parameter(
            Name=ssmParameterName,
            Type="String",
            Value=str(export2time),
            Overwrite=True)

    return 
