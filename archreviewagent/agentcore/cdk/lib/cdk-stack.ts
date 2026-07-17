import {
  AgentCoreApplication,
  AgentCoreMcp,
  type AgentCoreProjectSpec,
  type AgentCoreMcpSpec,
} from '@aws/agentcore-cdk';
import * as cdk from 'aws-cdk-lib';
import { CfnOutput, Stack, type StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface AgentCoreStackProps extends StackProps {
  /**
   * The AgentCore project specification containing agents, memories, and credentials.
   */
  spec: AgentCoreProjectSpec;
  /**
   * The MCP specification containing gateways and servers.
   */
  mcpSpec?: AgentCoreMcpSpec;
  /**
   * Credential provider ARNs from deployed state, keyed by credential name.
   */
  credentials?: Record<string, { credentialProviderArn: string; clientSecretArn?: string }>;
}

/**
 * CDK Stack that deploys AgentCore infrastructure.
 *
 * This is a thin wrapper that instantiates L3 constructs.
 * All resource logic and outputs are contained within the L3 constructs.
 */
export class AgentCoreStack extends Stack {
  /** The AgentCore application containing all agent environments */
  public readonly application: AgentCoreApplication;

  constructor(scope: Construct, id: string, props: AgentCoreStackProps) {
    super(scope, id, props);

    const { spec, mcpSpec, credentials } = props;

    // Create AgentCoreApplication with all agents
    this.application = new AgentCoreApplication(this, 'Application', {
      spec,
    });

    // Grant Memory write permissions to the agent runtime role.
    // The agent needs BatchCreateMemoryRecords to persist org rules.
    const agentEnv = this.application.environments?.get('archreviewer');
    if (agentEnv) {
      const memoryConstruct = this.application.memories?.get('archreview_memory');
      if (memoryConstruct) {
        agentEnv.runtime.addToPolicy(
          new cdk.aws_iam.PolicyStatement({
            actions: [
              'bedrock-agentcore:BatchCreateMemoryRecords',
            ],
            resources: [memoryConstruct.memoryArn],
          }),
        );
      }

      // S3 bucket for persisting async review results (the "laptop problem").
      // Results are stored as JSON objects keyed by session_key.
      const reviewsBucket = new cdk.aws_s3.Bucket(this, 'ReviewResultsBucket', {
        bucketName: `archreview-results-${this.account}-${this.region}`,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
        autoDeleteObjects: true,
        lifecycleRules: [{ expiration: cdk.Duration.days(30) }],
        encryption: cdk.aws_s3.BucketEncryption.S3_MANAGED,
        blockPublicAccess: cdk.aws_s3.BlockPublicAccess.BLOCK_ALL,
      });

      // Grant S3 read/write to the agent runtime role via IAM policy
      agentEnv.runtime.addToPolicy(
        new cdk.aws_iam.PolicyStatement({
          actions: ['s3:GetObject', 's3:PutObject'],
          resources: [reviewsBucket.arnForObjects('reviews/*')],
        }),
      );
      agentEnv.runtime.addToPolicy(
        new cdk.aws_iam.PolicyStatement({
          actions: ['s3:ListBucket'],
          resources: [reviewsBucket.bucketArn],
        }),
      );

      new CfnOutput(this, 'ReviewResultsBucketName', {
        description: 'S3 bucket for async review results',
        value: reviewsBucket.bucketName,
        exportName: `${this.stackName}-ReviewResultsBucket`,
      });
    }

    // Create AgentCoreMcp if there are gateways configured
    if (mcpSpec?.agentCoreGateways && mcpSpec.agentCoreGateways.length > 0) {
      new AgentCoreMcp(this, 'Mcp', {
        projectName: spec.name,
        mcpSpec,
        agentCoreApplication: this.application,
        credentials,
      });
    }

    // Stack-level output
    new CfnOutput(this, 'StackNameOutput', {
      description: 'Name of the CloudFormation Stack',
      value: this.stackName,
    });
  }
}
