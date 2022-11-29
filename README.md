# CloudWatchExtract

This Respository uses AWS CodePipeline to build out the following to extract CloudWatch Logs to S3:
<ul>
<li>An <b>Amazon DynamoDB</b> table to hold configuration information for</li>
<li>An <b>AWS Lambda</b>, that will extract the Amazon CloudWatch Logs defined in DynamoDB into an S3 bucket, which is triggered by</li>
<li>An <b>Amazon Cloudwatch Event Rule</b> that runs every 4 hours.</li>
<li>The <b>AWS IAM Role & Policy</b> for that Lambda's execution.</li>
<li>An <b>Amazon S3</b> bucket,</li>
<li>An <b>AWS IAM</b> Group for user(s) to be manually added, and</li>
<li>An <b>AWS IAM</b> Policy for this Group with Read access to the S3 bucket</li>
</ul>
as well as any other necessary AWS resources to suppor the above services.