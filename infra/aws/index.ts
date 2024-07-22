import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as op from "@1password/op-js";

import {
  getEnvironmentVars,
  syncSecretsAndGetRefs,
  sortByName,
} from "./secrets";

export const SCROLL_SECRETS_ARN = op.read.parse(
  "op://DevOps/passport-scroll-badge-service-production-infra/service/SCROLL_SECRETS_ARN"
);
export const ROUTE53_DOMAIN = op.read.parse(
  "op://DevOps/passport-scroll-badge-service-production-infra/service/ROUTE53_DOMAIN"
);
export const VC_SECRETS_ARN = op.read.parse(
  "op://DevOps/passport-scroll-badge-service-production-infra/service/VC_SECRETS_ARN"
);

export const DOCKER_IMAGE_TAG = `${process.env.SCROLL_BADGE_SERVICE_IMAGE_TAG || ""}`;

const current = aws.getCallerIdentity({});
const regionData = aws.getRegion({});
export const DOCKER_SCROLL_SERVICE_IMAGE = pulumi
  .all([current, regionData])
  .apply(
    ([acc, region]) =>
      `${acc.accountId}.dkr.ecr.${region.id}.amazonaws.com/scroll-badge-service:${DOCKER_IMAGE_TAG}`
  );
const stack = pulumi.getStack();

const defaultTags = {
  ManagedBy: "pulumi",
  PulumiStack: stack,
  Project: "scroll-badge",
};

const logsRetention = Object({
  review: 1,
  staging: 7,
  production: 30,
});

const coreInfraStack = new pulumi.StackReference(`gitcoin/core-infra/${stack}`);
const snsAlertsTopicArn = coreInfraStack.getOutput("snsAlertsTopicArn");
const passportInfraStack = new pulumi.StackReference(
  `gitcoin/passport/${stack}`
);

const passportClusterArn = passportInfraStack.getOutput("passportClusterArn");
export const passportClusterName = passportInfraStack.getOutput(
  "passportClusterName"
);
export const passportClusterNameArn = passportClusterArn;

const vpcId = coreInfraStack.getOutput("vpcId");

const albHttpsListenerArn = coreInfraStack.getOutput("coreAlbHttpsListenerArn");

const passwordManagerParams = {
  vault: "DevOps",
  repo: "passport-scroll-badge-service",
  env: stack,
  section: "service",
};

const scrollBadgeServiceSecretReferences = syncSecretsAndGetRefs({
  ...passwordManagerParams,
  targetSecretArn: SCROLL_SECRETS_ARN,
});

const secrets = [
  ...scrollBadgeServiceSecretReferences,
  {
    name: "SCROLL_BADGE_ATTESTATION_SIGNER_PRIVATE_KEY",
    valueFrom: `${VC_SECRETS_ARN}:SCROLL_BADGE_ATTESTATION_SIGNER_PRIVATE_KEY::`,
  },
].sort(sortByName);

const environment = getEnvironmentVars(passwordManagerParams);

const serviceRole = new aws.iam.Role("scroll-badge-ecs-role", {
  assumeRolePolicy: JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "EcsAssume",
        Action: "sts:AssumeRole",
        Effect: "Allow",
        Principal: {
          Service: "ecs-tasks.amazonaws.com",
        },
      },
    ],
  }),
  inlinePolicies: [
    {
      name: "allow_iam_secrets_access",
      policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Action: ["secretsmanager:GetSecretValue"],
            Effect: "Allow",
            Resource: [SCROLL_SECRETS_ARN, VC_SECRETS_ARN],
          },
        ],
      }),
    },
  ],
  managedPolicyArns: [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
  ],
  tags: {
    ...defaultTags,
  },
});

const serviceLogGroup = new aws.cloudwatch.LogGroup("scroll-badge-service", {
  name: "scroll-badge-service",
  retentionInDays: logsRetention[stack],
  tags: {
    ...defaultTags,
  },
});

const vpcPrivateSubnets = coreInfraStack.getOutput("privateSubnetIds");

//////////////////////////////////////////////////////////////
// Service SG
//////////////////////////////////////////////////////////////

const serviceSG = new aws.ec2.SecurityGroup(`scroll-badge-service-sg`, {
  name: `scroll-badge-service-sg`,
  vpcId: vpcId,
  description: `Security Group for scroll-badge-service service.`,
  tags: {
    ...defaultTags,
    Name: `scroll-badge-service`,
  },
});

// do no group the security group definition & rules in the same resource =>
// it will cause the sg to be destroyed and recreated everytime the rules change
// By managing them separately is easier to update the security group rules even outside of this stack
const sgIngressRule80 = new aws.ec2.SecurityGroupRule(
  `scroll-badge-service-sgr`,
  {
    securityGroupId: serviceSG.id,
    type: "ingress",
    fromPort: 80,
    toPort: 80,
    protocol: "tcp",
    cidrBlocks: ["0.0.0.0/0"], // TODO: improvements: allow only from the ALB's security group id
  },
  {
    dependsOn: [serviceSG],
  }
);

// Allow all outbound traffic
const sgEgressRule = new aws.ec2.SecurityGroupRule(
  `scroll-badge-service-all`,
  {
    securityGroupId: serviceSG.id,
    type: "egress",
    fromPort: 0,
    toPort: 0,
    protocol: "-1",
    cidrBlocks: ["0.0.0.0/0"],
  },
  {
    dependsOn: [serviceSG],
  }
);

//////////////////////////////////////////////////////////////
// Load Balancer listerner rule & target group
//////////////////////////////////////////////////////////////

const albTargetGroup = new aws.lb.TargetGroup(`scroll-badge-service-tg`, {
  name: `scroll-badge-service-tg`,
  vpcId: vpcId,
  healthCheck: {
    enabled: true,
    healthyThreshold: 3,
    interval: 30,
    matcher: "200",
    path: "/scroll/health",
    port: "traffic-port",
    protocol: "HTTP",
    timeout: 5,
    unhealthyThreshold: 5,
  },
  port: 80,
  protocol: "HTTP",
  targetType: "ip",
  tags: {
    ...defaultTags,
    Name: `scroll-badge-service-tg`,
  },
});

const albListenerRule = new aws.lb.ListenerRule(`scroll-badge-service-https`, {
  listenerArn: albHttpsListenerArn,
  priority: 90,
  actions: [
    {
      type: "forward",
      forward: {
        targetGroups: [{ arn: albTargetGroup.arn }],
      },
    },
  ],
  conditions: [
    {
      hostHeader: {
        values: [ROUTE53_DOMAIN],
      },
    },
    {
      pathPattern: {
        values: ["/scroll/*"],
      },
    },
  ],
  tags: {
    ...defaultTags,
    Name: `scroll-badge-service-https`,
  },
});

//////////////////////////////////////////////////////////////
// ECS Task & Service
//////////////////////////////////////////////////////////////

const service_data = DOCKER_SCROLL_SERVICE_IMAGE.apply((drk_image) => {
  const taskDefinition = new aws.ecs.TaskDefinition(`scroll-badge-service-td`, {
    family: `scroll-badge-service-td`,
    containerDefinitions: JSON.stringify([
      {
        name: "scroll-badge-service",
        image: drk_image,
        cpu: 512,
        memory: 1024,
        links: [],
        essential: true,
        portMappings: [
          {
            containerPort: 80,
            hostPort: 80,
            protocol: "tcp",
          },
        ],
        logConfiguration: {
          logDriver: "awslogs",
          options: {
            "awslogs-group": "scroll-badge-service", // "${serviceLogGroup.name}`,
            "awslogs-region": "us-west-2", // `${regionId}`,
            "awslogs-create-group": "true",
            "awslogs-stream-prefix": "scroll",
          },
        },
        mountPoints: [],
        volumesFrom: [],
        environment,
        secrets,
      },
    ]),
    executionRoleArn: serviceRole.arn,
    cpu: "512",
    memory: "1024",
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    tags: {
      ...defaultTags,
      EcsService: `scroll-badge-service`,
    },
  });

  const service = new aws.ecs.Service(
    `scroll-badge-service`,
    {
      cluster: passportClusterArn,
      desiredCount: 1,
      enableEcsManagedTags: true,
      enableExecuteCommand: false,
      launchType: "FARGATE",
      loadBalancers: [
        {
          containerName: "scroll-badge-service",
          containerPort: 80,
          targetGroupArn: albTargetGroup.arn,
        },
      ],
      name: `scroll-badge-service`,
      networkConfiguration: {
        subnets: vpcPrivateSubnets,
        securityGroups: [serviceSG.id],
      },
      propagateTags: "TASK_DEFINITION",
      taskDefinition: taskDefinition.arn,
      tags: {
        ...defaultTags,
        Name: `scroll-badge-service`,
      },
    },
    {
      dependsOn: [albTargetGroup, taskDefinition],
    }
  );

  // Manage Autoscaling
  const ecsAutoScalingTarget = new aws.appautoscaling.Target(
    `scroll-badge-service-scaling`,
    {
      maxCapacity: 10,
      minCapacity: 1,
      resourceId: pulumi.interpolate`service/${passportClusterName}/${service.name}`,
      scalableDimension: "ecs:service:DesiredCount",
      serviceNamespace: "ecs",
    }
  );

  const ecsAutoScalingPolicy = new aws.appautoscaling.Policy(
    "passport-autoscaling-policy",
    {
      policyType: "TargetTrackingScaling",
      resourceId: ecsAutoScalingTarget.resourceId,
      scalableDimension: ecsAutoScalingTarget.scalableDimension,
      serviceNamespace: ecsAutoScalingTarget.serviceNamespace,
      targetTrackingScalingPolicyConfiguration: {
        predefinedMetricSpecification: {
          predefinedMetricType: "ECSServiceAverageCPUUtilization",
        },
        targetValue: 70,
        scaleInCooldown: 300,
        scaleOutCooldown: 300,
      },
    }
  );

  const runningTaskCountAlarm = new aws.cloudwatch.MetricAlarm(
    `RunningTaskCount-scroll-badge`,
    {
      tags: { name: `RunningTaskCount-scroll-badge` },
      alarmActions: [snsAlertsTopicArn],
      okActions: [snsAlertsTopicArn],
      comparisonOperator: "GreaterThanThreshold",
      datapointsToAlarm: 1,
      dimensions: {
        ClusterName: passportClusterName,
        ServiceName: service.name,
      },
      evaluationPeriods: 1,
      metricName: "RunningTaskCount",
      name: `RunningTaskCount-scroll-badge`,
      namespace: "ECS/ContainerInsights",
      period: 300,
      statistic: "Average",
      threshold: 7,
    }
  );

  return { taskDefinition, service };
});

export const taskDefinitionRevision = service_data.taskDefinition.revision;
