import os
from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_efs as efs,
    aws_iam as iam,
    aws_elasticloadbalancingv2 as elbv2,
    aws_logs as logs,
    CfnOutput,
    Duration,
    RemovalPolicy,
)
from constructs import Construct
# No custom imports needed

class N8nStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create VPC
        vpc = ec2.Vpc(
            self, "N8nVPC",
            max_azs=2,
            nat_gateways=0,  # To save costs, we'll use public subnets
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                )
            ]
        )

        # Create ECS Cluster
        cluster = ecs.Cluster(
            self, "N8nCluster",
            vpc=vpc,
            container_insights=True
        )

        # Create ALB security group with no inbound access by default
        alb_security_group = ec2.SecurityGroup(
            self, "N8nALBSecurityGroup",
            vpc=vpc,
            description="Security group for n8n ALB (no access by default - add your IP after deployment)",
            allow_all_outbound=True
        )
        
        # Check for IPs from environment variable
        allowed_ips = os.environ.get('ALLOWED_IPS', '')
        if allowed_ips:
            # Add ingress rules for each allowed IP
            for ip in [ip.strip() for ip in allowed_ips.split(',') if ip.strip()]:
                # Security check: Prevent open access
                if ip == "0.0.0.0/0":
                    print(f"⚠️ ERROR: Open access (0.0.0.0/0) is not allowed for security reasons.")
                    print(f"Please specify specific IP addresses or CIDR blocks.")
                    continue
                    
                print(f"Adding access for IP: {ip}")
                
                # Add HTTP access
                alb_security_group.add_ingress_rule(
                    ec2.Peer.ipv4(ip if '/' in ip else f"{ip}/32"),
                    ec2.Port.tcp(80),
                    f"HTTP access from {ip}"
                )
                
                # Add HTTPS access
                alb_security_group.add_ingress_rule(
                    ec2.Peer.ipv4(ip if '/' in ip else f"{ip}/32"),
                    ec2.Port.tcp(443),
                    f"HTTPS access from {ip}"
                )
        else:
            print("⚠️ WARNING: No IP addresses specified. Access will be completely restricted.")
            print("You must add your IP address after deployment using the manage-ip-access.sh script.")
        
        # Create ECS security group that only accepts traffic from ALB
        ecs_security_group = ec2.SecurityGroup(
            self, "N8nECSSecurityGroup",
            vpc=vpc,
            description="Security group for n8n ECS tasks - ALB access only",
            allow_all_outbound=True
        )
        
        # Allow traffic from ALB security group on n8n port (5678)
        ecs_security_group.add_ingress_rule(
            ec2.Peer.security_group_id(alb_security_group.security_group_id),
            ec2.Port.tcp(5678),
            "Allow traffic from ALB to n8n"
        )
        
        # Create Security Group for EFS
        efs_security_group = ec2.SecurityGroup(
            self, "EfsSecurityGroup",
            vpc=vpc,
            description="Security group for EFS",
            allow_all_outbound=True
        )
        
        # Allow NFS traffic from the ECS security group to EFS
        efs_security_group.add_ingress_rule(
            ecs_security_group,
            ec2.Port.tcp(2049),
            "Allow NFS traffic from n8n tasks"
        )

        # Create EFS File System for n8n data persistence
        file_system = efs.FileSystem(
            self, "N8nFileSystem",
            vpc=vpc,
            security_group=efs_security_group,
            removal_policy=RemovalPolicy.DESTROY,  # For POC only, use RETAIN for production
            lifecycle_policy=efs.LifecyclePolicy.AFTER_14_DAYS,  # Move files to infrequent access after 14 days
            performance_mode=efs.PerformanceMode.GENERAL_PURPOSE,
            throughput_mode=efs.ThroughputMode.BURSTING
        )

        # Create access point for n8n data
        access_point = file_system.add_access_point(
            "N8nAccessPoint",
            create_acl=efs.Acl(
                owner_uid="1000",
                owner_gid="1000",
                permissions="755"
            ),
            path="/n8n-data",
            posix_user=efs.PosixUser(
                uid="1000",
                gid="1000"
            )
        )

        # Create Task Execution Role
        execution_role = iam.Role(
            self, "N8nTaskExecutionRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonECSTaskExecutionRolePolicy")
            ]
        )

        # Create Task Role with permissions for AWS services
        task_role = iam.Role(
            self, "N8nTaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com")
        )

        # Add permissions for S3
        task_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3ReadOnlyAccess")
        )



        # Add permissions for SNS (User Messaging)
        task_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "sns:Publish"
                ],
                resources=["*"]
            )
        )
        
        # Add explicit permissions for EFS
        task_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "elasticfilesystem:ClientMount",
                    "elasticfilesystem:ClientWrite",
                    "elasticfilesystem:ClientRootAccess",
                    "elasticfilesystem:DescribeMountTargets"
                ],
                resources=["*"]
            )
        )
        
        # Add permissions for internet access and npm
        task_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:CreateNetworkInterface",
                    "ec2:DeleteNetworkInterface",
                    "ec2:DescribeInstances",
                    "ec2:AttachNetworkInterface"
                ],
                resources=["*"]
            )
        )

        # Create Log Group
        log_group = logs.LogGroup(
            self, "N8nLogGroup",
            removal_policy=RemovalPolicy.DESTROY,  # For POC only, use RETAIN for production
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Create Task Definition
        task_definition = ecs.FargateTaskDefinition(
            self, "N8nTaskDefinition",
            memory_limit_mib=2048,
            cpu=1024,
            execution_role=execution_role,
            task_role=task_role
        )

        # Add EFS volume to task definition
        task_definition.add_volume(
            name="n8n-data",
            efs_volume_configuration=ecs.EfsVolumeConfiguration(
                file_system_id=file_system.file_system_id,
                transit_encryption="ENABLED",
                authorization_config=ecs.AuthorizationConfig(
                    access_point_id=access_point.access_point_id,
                    iam="ENABLED"
                )
            )
        )

        # Create Load Balancer with IP-restricted security group
        lb = elbv2.ApplicationLoadBalancer(
            self, "N8nLoadBalancer",
            vpc=vpc,
            internet_facing=True,
            security_group=alb_security_group
        )

        # Create Target Group
        target_group = elbv2.ApplicationTargetGroup(
            self, "N8nTargetGroup",
            vpc=vpc,
            port=5678,
            protocol=elbv2.ApplicationProtocol.HTTP,
            target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(
                path="/",
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5)
            )
        )

        # Create Listener
        listener = lb.add_listener(
            "N8nListener",
            port=80,
            default_target_groups=[target_group]
        )

        # Add n8n container to task definition
        container = task_definition.add_container(
            "n8n",
            image=ecs.ContainerImage.from_registry("n8nio/n8n:latest"),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="n8n",
                log_group=log_group
            ),
            environment={
                "N8N_PORT": "5678",
                "N8N_PROTOCOL": "http",
                "NODE_ENV": "production",
                "GENERIC_TIMEZONE": "UTC",
                "N8N_SECURE_COOKIE": "false",
                "N8N_DISABLE_PRODUCTION_MAIN_PROCESS": "false",
                "NODE_FUNCTION_ALLOW_EXTERNAL": "true",
                "N8N_METRICS": "false",
                "WEBHOOK_URL": f"http://{lb.load_balancer_dns_name}",
                # Additional environment variables for community nodes
                "NPM_CONFIG_UNSAFE_PERM": "true",
                "N8N_COMMUNITY_NODES_ENABLED": "true",
                "N8N_COMMUNITY_NODES_NPM_REGISTRY": "https://registry.npmjs.org/"
            },
            port_mappings=[
                ecs.PortMapping(
                    container_port=5678,
                    host_port=5678,
                    protocol=ecs.Protocol.TCP
                )
            ]
        )

        # Add mount point for EFS
        container.add_mount_points(
            ecs.MountPoint(
                container_path="/home/node/.n8n",
                source_volume="n8n-data",
                read_only=False
            )
        )

        # Create ECS Service
        service = ecs.FargateService(
            self, "N8nService",
            cluster=cluster,
            task_definition=task_definition,
            desired_count=1,
            security_groups=[ecs_security_group],
            assign_public_ip=True,  # Required for tasks in public subnets
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC)
        )

        # Add service as target to target group
        service.attach_to_application_target_group(target_group)

        # Output the URL to access n8n
        CfnOutput(
            self, "N8nURL",
            value=f"http://{lb.load_balancer_dns_name}",
            description="URL to access n8n"
        )
        
        # Output the EFS File System ID for troubleshooting
        CfnOutput(
            self, "N8nFileSystemId",
            value=file_system.file_system_id,
            description="EFS File System ID"
        )
        
        # Output security group IDs for IP access management
        CfnOutput(
            self, "ALBSecurityGroupId",
            value=alb_security_group.security_group_id,
            description="Security Group ID for ALB (for IP access management)"
        )
        
        CfnOutput(
            self, "ECSSecurityGroupId",
            value=ecs_security_group.security_group_id,
            description="Security Group ID for ECS tasks"
        )
        
        # Add security warning and instructions
        CfnOutput(
            self, "SecurityWarning",
            value="⚠️ IMPORTANT: By default, this deployment has no inbound access allowed. You must specify IPs during deployment with ALLOWED_IPS or add them after deployment.",
            description="Security warning"
        )
        
        # Add additional outputs for IP access management
        CfnOutput(
            self, "IPAccessManagement",
            value=f"To manage IP access restrictions, use: ./manage-ip-access.sh --sg-id {alb_security_group.security_group_id}",
            description="Command for managing IP access restrictions"
        )
        
        CfnOutput(
            self, "IPAccessDocumentation",
            value="For detailed instructions on IP access management, see: docs/ip-access-control.md",
            description="Documentation for IP access management"
        )
