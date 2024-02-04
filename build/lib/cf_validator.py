import json
import sys
import yaml
import requests
import os
import random
import string
import re

def generate_unique_id():
    characters = string.ascii_letters + string.digits
    unique_id = ''.join(random.choice(characters) for _ in range(32))
    print(unique_id[:8]+'-'+unique_id[8:12]+'-'+unique_id[12:16]+'-'+unique_id[16:20]+'-'+unique_id[20:])

def is_valid_json(json_str):
    try:
        json.loads(json_str)
        return True, None
    except json.JSONDecodeError as e:
        return False, f"Error: The provided JSON file is not in the expected format.\nLocation: Line {e.lineno}, Column {e.colno}\nDetails: {e.msg}"

def is_valid_yaml(file_path):
    try:
        file=open(file_path, 'r')
        yaml.safe_load(file)
        return True
    except yaml.YAMLError as e:
        words=str(e)
        check=words.split()
        for i in check:
            if i in intrinsic:
                signal=True
            else:
                signal=False
            if signal:
                break
        if signal:
            return True
        else:
            return f"Error: The provided YAML file does not adhere to the expected format.\nDetails: {e}"
        
def replace_s_exclamation(dictionary):
    new_dict = {}
    for key, value in dictionary.items():
        if isinstance(value, dict):
            new_dict[key] = replace_s_exclamation(value)
        elif isinstance(value, list):
            new_list = []
            for item in value:
                if isinstance(item, str):
                    new_list.append(item.replace('s!', '!'))
                elif isinstance(item, dict):
                    new_list.append(replace_s_exclamation(item))
                else:
                    new_list.append(item)
            new_dict[key] = new_list
        elif isinstance(value, str):
            new_dict[key] = value.replace('s!', '!')
        else:
            new_dict[key] = value
    return new_dict

def extract_ref_values_json(data):
    ref_values = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "Ref":
                ref_values.append(value)
            else:
                ref_values.extend(extract_ref_values_json(value))
    elif isinstance(data, list):
        for item in data:
            ref_values.extend(extract_ref_values_json(item))
    return ref_values

def extract_ref_values_yaml(data):
    ref_values = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str) and value.startswith('!Ref'):
                ref_values.append(value.split(' ')[1])  # Extract the value after !Ref
            ref_values.extend(extract_ref_values_yaml(value))
    elif isinstance(data, list):
        for item in data:
            ref_values.extend(extract_ref_values_yaml(item))
    return ref_values

def has_intrinsic_functions_in_parameters(template):  
    if "Parameters" in template:
        parameters = template["Parameters"]
        for param_name, param_details in parameters.items():
            for func in intrinsic_functions:
                if func in param_details.get("Default", ""):
                    return True
    return False

def extract_depends_on(resource_properties):
    if "DependsOn" in resource_properties:
        depends_on = resource_properties["DependsOn"]
        if isinstance(depends_on, str):
            return [depends_on]
        elif isinstance(depends_on, list):
            return depends_on
    return []

def get_url_contents(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  
        return response.text
    except requests.exceptions.RequestException as e:
        print("An error occurred while attempting to retrieve the URL:\nDetails: {e}")
        return None
    
def file_size_path(file_path):
    return os.path.getsize(file_path)

def file_size_url(url):
    response=requests.head(url)
    return int(response.headers['Content-Length'])

checklist=[]

parameter_types=[]

all_depends_on=[]

resource_types=[]

intrinsic_functions=['Ref', 'Fn::Sub', 'Fn::GetAtt', 'Fn::Join', 'Fn::If', 'Fn::ImportValue', 'Fn::FindInMap']

intrinsic=["'!Ref'", "'!Sub'", "'!GetAtt'", "'!ImportValue'", "'!Join'", "'!Select'", 
        "'!Split'", "'!Base64'", "'!Cidr'", "'!Transform'", "'!Not'", "'!Equals'", "'!FindInMap'", "'!If'"]


valid_aws_resource_types=['AWS::ACMPCA::Certificate', 'AWS::ACMPCA::CertificateAuthority', 'AWS::ACMPCA::CertificateAuthorityActivation', 
                          'AWS::ACMPCA::Permission', 'AWS::Amplify::App', 'AWS::Amplify::Branch', 'AWS::Amplify::Domain', 
                          'AWS::AmplifyUIBuilder::Component', 'AWS::AmplifyUIBuilder::Form', 'AWS::AmplifyUIBuilder::Theme', 
                          'AWS::ApiGateway::Account', 'AWS::ApiGateway::ApiKey', 'AWS::ApiGateway::Authorizer', 
                          'AWS::ApiGateway::BasePathMapping', 'AWS::ApiGateway::ClientCertificate', 'AWS::ApiGateway::Deployment', 
                          'AWS::ApiGateway::DocumentationPart', 'AWS::ApiGateway::DocumentationVersion', 'AWS::ApiGateway::DomainName', 
                          'AWS::ApiGateway::GatewayResponse', 'AWS::ApiGateway::Method', 'AWS::ApiGateway::Model', 
                          'AWS::ApiGateway::RequestValidator', 'AWS::ApiGateway::Resource', 'AWS::ApiGateway::RestApi', 
                          'AWS::ApiGateway::Stage', 'AWS::ApiGateway::UsagePlan', 'AWS::ApiGateway::UsagePlanKey', 
                          'AWS::ApiGateway::VpcLink', 'AWS::ApiGatewayV2::Api', 'AWS::ApiGatewayV2::ApiGatewayManagedOverrides', 
                          'AWS::ApiGatewayV2::ApiMapping', 'AWS::ApiGatewayV2::Authorizer', 'AWS::ApiGatewayV2::Deployment', 
                          'AWS::ApiGatewayV2::DomainName', 'AWS::ApiGatewayV2::Integration', 'AWS::ApiGatewayV2::IntegrationResponse', 
                          'AWS::ApiGatewayV2::Model', 'AWS::ApiGatewayV2::Route', 'AWS::ApiGatewayV2::RouteResponse', 
                          'AWS::ApiGatewayV2::Stage', 'AWS::ApiGatewayV2::VpcLink', 'AWS::AppConfig::Application', 
                          'AWS::AppConfig::ConfigurationProfile', 'AWS::AppConfig::Deployment', 'AWS::AppConfig::DeploymentStrategy', 
                          'AWS::AppConfig::Environment', 'AWS::AppConfig::Extension', 'AWS::AppConfig::ExtensionAssociation', 
                          'AWS::AppConfig::HostedConfigurationVersion', 'AWS::AppFlow::Connector', 'AWS::AppFlow::ConnectorProfile', 
                          'AWS::AppFlow::Flow', 'AWS::AppIntegrations::DataIntegration', 'AWS::AppIntegrations::EventIntegration', 
                          'AWS::ApplicationAutoScaling::ScalableTarget', 'AWS::ApplicationAutoScaling::ScalingPolicy', 
                          'AWS::AppMesh::GatewayRoute', 'AWS::AppMesh::Mesh', 'AWS::AppMesh::Route', 'AWS::AppMesh::VirtualGateway', 
                          'AWS::AppMesh::VirtualNode', 'AWS::AppMesh::VirtualRouter', 'AWS::AppMesh::VirtualService', 
                          'AWS::AppRunner::AutoScalingConfiguration', 'AWS::AppRunner::ObservabilityConfiguration', 
                          'AWS::AppRunner::Service', 'AWS::AppRunner::VpcConnector', 'AWS::AppRunner::VpcIngressConnection', 
                          'AWS::AppStream::AppBlock', 'AWS::AppStream::AppBlockBuilder', 'AWS::AppStream::Application', 
                          'AWS::AppStream::ApplicationEntitlementAssociation', 'AWS::AppStream::ApplicationFleetAssociation', 
                          'AWS::AppStream::DirectoryConfig', 'AWS::AppStream::Entitlement', 'AWS::AppStream::Fleet', 
                          'AWS::AppStream::ImageBuilder', 'AWS::AppStream::Stack', 'AWS::AppStream::StackFleetAssociation', 
                          'AWS::AppStream::StackUserAssociation', 'AWS::AppStream::User', 'AWS::AppSync::ApiCache', 'AWS::AppSync::ApiKey', 
                          'AWS::AppSync::DataSource', 'AWS::AppSync::DomainName', 'AWS::AppSync::DomainNameApiAssociation', 
                          'AWS::AppSync::FunctionConfiguration', 'AWS::AppSync::GraphQLApi', 'AWS::AppSync::GraphQLSchema', 
                          'AWS::AppSync::Resolver', 'AWS::AppSync::SourceApiAssociation', 'Alexa::ASK::Skill', 
                          'AWS::Athena::CapacityReservation', 'AWS::Athena::DataCatalog', 'AWS::Athena::NamedQuery', 
                          'AWS::Athena::PreparedStatement', 'AWS::Athena::WorkGroup', 'AWS::AuditManager::Assessment', 
                          'AWS::AutoScalingPlans::ScalingPlan', 'AWS::Backup::BackupPlan', 'AWS::Backup::BackupSelection', 
                          'AWS::Backup::BackupVault', 'AWS::Backup::Framework', 'AWS::Backup::ReportPlan', 'AWS::BackupGateway::Hypervisor', 
                          'AWS::Batch::ComputeEnvironment', 'AWS::Batch::JobDefinition', 'AWS::Batch::JobQueue', 
                          'AWS::Batch::SchedulingPolicy', 'AWS::BillingConductor::BillingGroup', 'AWS::BillingConductor::CustomLineItem', 
                          'AWS::BillingConductor::PricingPlan', 'AWS::BillingConductor::PricingRule', 'AWS::Budgets::Budget', 
                          'AWS::Budgets::BudgetsAction', 'AWS::CertificateManager::Account', 'AWS::CertificateManager::Certificate', 
                          'AWS::Chatbot::MicrosoftTeamsChannelConfiguration', 'AWS::Chatbot::SlackChannelConfiguration', 
                          'AWS::CleanRooms::Collaboration', 'AWS::CleanRooms::ConfiguredTable', 'AWS::CleanRooms::ConfiguredTableAssociation', 
                          'AWS::CleanRooms::Membership', 'AWS::Cloud9::EnvironmentEC2', 'AWS::CloudFormation::CustomResource', 
                          'AWS::CloudFormation::HookDefaultVersion', 'AWS::CloudFormation::HookTypeConfig', 'AWS::CloudFormation::HookVersion', 
                          'AWS::CloudFormation::Macro', 'AWS::CloudFormation::ModuleDefaultVersion', 'AWS::CloudFormation::ModuleVersion', 
                          'AWS::CloudFormation::PublicTypeVersion', 'AWS::CloudFormation::Publisher', 
                          'AWS::CloudFormation::ResourceDefaultVersion', 'AWS::CloudFormation::ResourceVersion', 'AWS::CloudFormation::Stack', 
                          'AWS::CloudFormation::StackSet', 'AWS::CloudFormation::TypeActivation', 'AWS::CloudFormation::WaitCondition', 
                          'AWS::CloudFormation::WaitConditionHandle', 'AWS::CloudFront::CachePolicy', 
                          'AWS::CloudFront::CloudFrontOriginAccessIdentity', 'AWS::CloudFront::ContinuousDeploymentPolicy', 
                          'AWS::CloudFront::Distribution', 'AWS::CloudFront::Function', 'AWS::CloudFront::KeyGroup', 
                          'AWS::CloudFront::MonitoringSubscription', 'AWS::CloudFront::OriginAccessControl', 
                          'AWS::CloudFront::OriginRequestPolicy', 'AWS::CloudFront::PublicKey', 'AWS::CloudFront::RealtimeLogConfig', 
                          'AWS::CloudFront::ResponseHeadersPolicy', 'AWS::CloudFront::StreamingDistribution', 
                          'AWS::ServiceDiscovery::HttpNamespace', 'AWS::ServiceDiscovery::Instance', 'AWS::ServiceDiscovery::PrivateDnsNamespace', 
                          'AWS::ServiceDiscovery::PublicDnsNamespace', 'AWS::ServiceDiscovery::Service', 'AWS::CloudTrail::Channel', 
                          'AWS::CloudTrail::EventDataStore', 'AWS::CloudTrail::ResourcePolicy', 'AWS::CloudTrail::Trail', 'AWS::CloudWatch::Alarm', 
                          'AWS::CloudWatch::AnomalyDetector', 'AWS::CloudWatch::CompositeAlarm', 'AWS::CloudWatch::Dashboard', 
                          'AWS::CloudWatch::InsightRule', 'AWS::CloudWatch::MetricStream', 'AWS::ApplicationInsights::Application', 
                          'AWS::Logs::AccountPolicy', 'AWS::Logs::Destination', 'AWS::Logs::LogGroup', 'AWS::Logs::LogStream', 
                          'AWS::Logs::MetricFilter', 'AWS::Logs::QueryDefinition', 'AWS::Logs::ResourcePolicy', 'AWS::Logs::SubscriptionFilter', 
                          'AWS::Synthetics::Canary', 'AWS::Synthetics::Group', 'AWS::CodeArtifact::Domain', 'AWS::CodeArtifact::Repository', 
                          'AWS::CodeBuild::Project', 'AWS::CodeBuild::ReportGroup', 'AWS::CodeBuild::SourceCredential', 'AWS::CodeCommit::Repository', 
                          'AWS::CodeDeploy::Application', 'AWS::CodeDeploy::DeploymentConfig', 'AWS::CodeDeploy::DeploymentGroup', 
                          'AWS::CodeGuruProfiler::ProfilingGroup', 'AWS::CodeGuruReviewer::RepositoryAssociation', 'AWS::CodePipeline::CustomActionType', 
                          'AWS::CodePipeline::Pipeline', 'AWS::CodePipeline::Webhook', 'AWS::CodeStar::GitHubRepository', 
                          'AWS::CodeStarConnections::Connection', 'AWS::CodeStarNotifications::NotificationRule', 'AWS::Cognito::IdentityPool', 
                          'AWS::Cognito::IdentityPoolPrincipalTag', 'AWS::Cognito::IdentityPoolRoleAttachment', 'AWS::Cognito::UserPool', 
                          'AWS::Cognito::UserPoolClient', 'AWS::Cognito::UserPoolDomain', 'AWS::Cognito::UserPoolGroup', 
                          'AWS::Cognito::UserPoolIdentityProvider', 'AWS::Cognito::UserPoolResourceServer', 'AWS::Cognito::UserPoolRiskConfigurationAttachment', 
                          'AWS::Cognito::UserPoolUICustomizationAttachment', 'AWS::Cognito::UserPoolUser', 'AWS::Cognito::UserPoolUserToGroupAttachment', 
                          'AWS::Comprehend::DocumentClassifier', 'AWS::Comprehend::Flywheel', 'AWS::Config::AggregationAuthorization', 'AWS::Config::ConfigRule', 
                          'AWS::Config::ConfigurationAggregator', 'AWS::Config::ConfigurationRecorder', 'AWS::Config::ConformancePack', 
                          'AWS::Config::DeliveryChannel', 'AWS::Config::OrganizationConfigRule', 'AWS::Config::OrganizationConformancePack', 
                          'AWS::Config::RemediationConfiguration', 'AWS::Config::StoredQuery', 'AWS::Connect::ApprovedOrigin', 'AWS::Connect::ContactFlow', 
                          'AWS::Connect::ContactFlowModule', 'AWS::Connect::EvaluationForm', 'AWS::Connect::HoursOfOperation', 'AWS::Connect::Instance', 
                          'AWS::Connect::InstanceStorageConfig', 'AWS::Connect::IntegrationAssociation', 'AWS::Connect::PhoneNumber', 'AWS::Connect::Prompt', 
                          'AWS::Connect::Queue', 'AWS::Connect::QuickConnect', 'AWS::Connect::RoutingProfile', 'AWS::Connect::Rule', 'AWS::Connect::SecurityKey', 
                          'AWS::Connect::TaskTemplate', 'AWS::Connect::TrafficDistributionGroup', 'AWS::Connect::User', 'AWS::Connect::UserHierarchyGroup', 
                          'AWS::ConnectCampaigns::Campaign', 'AWS::ControlTower::EnabledControl', 'AWS::CustomerProfiles::CalculatedAttributeDefinition', 
                          'AWS::CustomerProfiles::Domain', 'AWS::CustomerProfiles::EventStream', 'AWS::CustomerProfiles::Integration', 
                          'AWS::CustomerProfiles::ObjectType', 'AWS::CE::AnomalyMonitor', 'AWS::CE::AnomalySubscription', 'AWS::CE::CostCategory', 
                          'AWS::CUR::ReportDefinition', 'AWS::DataBrew::Dataset', 'AWS::DataBrew::Job', 'AWS::DataBrew::Project', 'AWS::DataBrew::Recipe', 
                          'AWS::DataBrew::Ruleset', 'AWS::DataBrew::Schedule', 'AWS::DLM::LifecyclePolicy', 'AWS::DataPipeline::Pipeline', 
                          'AWS::DataSync::Agent', 'AWS::DataSync::LocationAzureBlob', 'AWS::DataSync::LocationEFS', 'AWS::DataSync::LocationFSxLustre', 
                          'AWS::DataSync::LocationFSxONTAP', 'AWS::DataSync::LocationFSxOpenZFS', 'AWS::DataSync::LocationFSxWindows', 
                          'AWS::DataSync::LocationHDFS', 'AWS::DataSync::LocationNFS', 'AWS::DataSync::LocationObjectStorage', 'AWS::DataSync::LocationS3', 
                          'AWS::DataSync::LocationSMB', 'AWS::DataSync::StorageSystem', 'AWS::DataSync::Task', 'AWS::DAX::Cluster', 'AWS::DAX::ParameterGroup', 
                          'AWS::DAX::SubnetGroup', 'AWS::Detective::Graph', 'AWS::Detective::MemberInvitation', 'AWS::Detective::OrganizationAdmin', 
                          'AWS::DeviceFarm::DevicePool', 'AWS::DeviceFarm::InstanceProfile', 'AWS::DeviceFarm::NetworkProfile', 'AWS::DeviceFarm::Project', 
                          'AWS::DeviceFarm::TestGridProject', 'AWS::DeviceFarm::VPCEConfiguration', 'AWS::DevOpsGuru::LogAnomalyDetectionIntegration', 
                          'AWS::DevOpsGuru::NotificationChannel', 'AWS::DevOpsGuru::ResourceCollection', 'AWS::DirectoryService::MicrosoftAD', 
                          'AWS::DirectoryService::SimpleAD', 'AWS::DMS::Certificate', 'AWS::DMS::Endpoint', 'AWS::DMS::EventSubscription', 
                          'AWS::DMS::ReplicationConfig', 'AWS::DMS::ReplicationInstance', 'AWS::DMS::ReplicationSubnetGroup', 'AWS::DMS::ReplicationTask', 
                          'AWS::DocDB::DBCluster', 'AWS::DocDB::DBClusterParameterGroup', 'AWS::DocDB::DBInstance', 'AWS::DocDB::DBSubnetGroup', 
                          'AWS::DocDBElastic::Cluster', 'AWS::DynamoDB::GlobalTable', 'AWS::DynamoDB::Table', 'AWS::EC2::CapacityReservation', 
                          'AWS::EC2::CapacityReservationFleet', 'AWS::EC2::CarrierGateway', 'AWS::EC2::ClientVpnAuthorizationRule', 'AWS::EC2::ClientVpnEndpoint', 
                          'AWS::EC2::ClientVpnRoute', 'AWS::EC2::ClientVpnTargetNetworkAssociation', 'AWS::EC2::CustomerGateway', 'AWS::EC2::DHCPOptions', 
                          'AWS::EC2::EC2Fleet', 'AWS::EC2::EgressOnlyInternetGateway', 'AWS::EC2::EIP', 'AWS::EC2::EIPAssociation', 
                          'AWS::EC2::EnclaveCertificateIamRoleAssociation', 'AWS::EC2::FlowLog', 'AWS::EC2::GatewayRouteTableAssociation', 'AWS::EC2::Host', 
                          'AWS::EC2::Instance', 'AWS::EC2::InstanceConnectEndpoint', 'AWS::EC2::InternetGateway', 'AWS::EC2::IPAM', 'AWS::EC2::IPAMAllocation', 
                          'AWS::EC2::IPAMPool', 'AWS::EC2::IPAMPoolCidr', 'AWS::EC2::IPAMResourceDiscovery', 'AWS::EC2::IPAMResourceDiscoveryAssociation', 
                          'AWS::EC2::IPAMScope', 'AWS::EC2::KeyPair', 'AWS::EC2::LaunchTemplate', 'AWS::EC2::LocalGatewayRoute', 
                          'AWS::EC2::LocalGatewayRouteTable', 'AWS::EC2::LocalGatewayRouteTableVirtualInterfaceGroupAssociation', 
                          'AWS::EC2::LocalGatewayRouteTableVPCAssociation', 'AWS::EC2::NatGateway', 'AWS::EC2::NetworkAcl', 'AWS::EC2::NetworkAclEntry', 
                          'AWS::EC2::NetworkInsightsAccessScope', 'AWS::EC2::NetworkInsightsAccessScopeAnalysis', 'AWS::EC2::NetworkInsightsAnalysis', 
                          'AWS::EC2::NetworkInsightsPath', 'AWS::EC2::NetworkInterface', 'AWS::EC2::NetworkInterfaceAttachment', 
                          'AWS::EC2::NetworkInterfacePermission', 'AWS::EC2::NetworkPerformanceMetricSubscription', 'AWS::EC2::PlacementGroup', 
                          'AWS::EC2::PrefixList', 'AWS::EC2::Route', 'AWS::EC2::RouteTable', 'AWS::EC2::SecurityGroup', 'AWS::EC2::SecurityGroupEgress', 
                          'AWS::EC2::SecurityGroupIngress', 'AWS::EC2::SpotFleet', 'AWS::EC2::Subnet', 'AWS::EC2::SubnetCidrBlock', 
                          'AWS::EC2::SubnetNetworkAclAssociation', 'AWS::EC2::SubnetRouteTableAssociation', 'AWS::EC2::TrafficMirrorFilter', 
                          'AWS::EC2::TrafficMirrorFilterRule', 'AWS::EC2::TrafficMirrorSession', 'AWS::EC2::TrafficMirrorTarget', 'AWS::EC2::TransitGateway', 
                          'AWS::EC2::TransitGatewayAttachment', 'AWS::EC2::TransitGatewayConnect', 'AWS::EC2::TransitGatewayMulticastDomain', 
                          'AWS::EC2::TransitGatewayMulticastDomainAssociation', 'AWS::EC2::TransitGatewayMulticastGroupMember', 
                          'AWS::EC2::TransitGatewayMulticastGroupSource', 'AWS::EC2::TransitGatewayPeeringAttachment', 'AWS::EC2::TransitGatewayRoute', 
                          'AWS::EC2::TransitGatewayRouteTable', 'AWS::EC2::TransitGatewayRouteTableAssociation', 'AWS::EC2::TransitGatewayRouteTablePropagation', 
                          'AWS::EC2::TransitGatewayVpcAttachment', 'AWS::EC2::VerifiedAccessEndpoint', 'AWS::EC2::VerifiedAccessGroup', 
                          'AWS::EC2::VerifiedAccessInstance', 'AWS::EC2::VerifiedAccessTrustProvider', 'AWS::EC2::Volume', 'AWS::EC2::VolumeAttachment', 
                          'AWS::EC2::VPC', 'AWS::EC2::VPCCidrBlock', 'AWS::EC2::VPCDHCPOptionsAssociation', 'AWS::EC2::VPCEndpoint', 
                          'AWS::EC2::VPCEndpointConnectionNotification', 'AWS::EC2::VPCEndpointService', 'AWS::EC2::VPCEndpointServicePermissions', 
                          'AWS::EC2::VPCGatewayAttachment', 'AWS::EC2::VPCPeeringConnection', 'AWS::EC2::VPNConnection', 'AWS::EC2::VPNConnectionRoute', 
                          'AWS::EC2::VPNGateway', 'AWS::EC2::VPNGatewayRoutePropagation', 'AWS::AutoScaling::AutoScalingGroup', 
                          'AWS::AutoScaling::LaunchConfiguration', 'AWS::AutoScaling::LifecycleHook', 'AWS::AutoScaling::ScalingPolicy', 
                          'AWS::AutoScaling::ScheduledAction', 'AWS::AutoScaling::WarmPool', 'AWS::ECR::PublicRepository', 'AWS::ECR::PullThroughCacheRule', 
                          'AWS::ECR::RegistryPolicy', 'AWS::ECR::ReplicationConfiguration', 'AWS::ECR::Repository', 'AWS::ECS::CapacityProvider', 
                          'AWS::ECS::Cluster', 'AWS::ECS::ClusterCapacityProviderAssociations', 'AWS::ECS::PrimaryTaskSet', 'AWS::ECS::Service', 
                          'AWS::ECS::TaskDefinition', 'AWS::ECS::TaskSet', 'AWS::EFS::AccessPoint', 'AWS::EFS::FileSystem', 'AWS::EFS::MountTarget', 
                          'AWS::EKS::Addon', 'AWS::EKS::Cluster', 'AWS::EKS::FargateProfile', 'AWS::EKS::IdentityProviderConfig', 'AWS::EKS::Nodegroup', 
                          'AWS::ElasticBeanstalk::Application', 'AWS::ElasticBeanstalk::ApplicationVersion', 'AWS::ElasticBeanstalk::ConfigurationTemplate', 
                          'AWS::ElasticBeanstalk::Environment', 'AWS::ElasticLoadBalancing::LoadBalancer', 'AWS::ElasticLoadBalancingV2::Listener', 
                          'AWS::ElasticLoadBalancingV2::ListenerCertificate', 'AWS::ElasticLoadBalancingV2::ListenerRule', 'AWS::ElasticLoadBalancingV2::LoadBalancer', 
                          'AWS::ElasticLoadBalancingV2::TargetGroup', 'AWS::EMR::Cluster', 'AWS::EMR::InstanceFleetConfig', 'AWS::EMR::InstanceGroupConfig', 
                          'AWS::EMR::SecurityConfiguration', 'AWS::EMR::Step', 'AWS::EMR::Studio', 'AWS::EMR::StudioSessionMapping', 
                          'AWS::EMRServerless::Application', 'AWS::EMRContainers::VirtualCluster', 'AWS::ElastiCache::CacheCluster', 
                          'AWS::ElastiCache::GlobalReplicationGroup', 'AWS::ElastiCache::ParameterGroup', 'AWS::ElastiCache::ReplicationGroup', 
                          'AWS::ElastiCache::SecurityGroup', 'AWS::ElastiCache::SecurityGroupIngress', 'AWS::ElastiCache::SubnetGroup', 'AWS::ElastiCache::User', 
                          'AWS::ElastiCache::UserGroup', 'AWS::EntityResolution::SchemaMapping', 'AWS::Events::ApiDestination', 'AWS::Events::Archive', 
                          'AWS::Events::Connection', 'AWS::Events::Endpoint', 'AWS::Events::EventBus', 'AWS::Events::EventBusPolicy', 'AWS::Events::Rule', 
                          'AWS::Pipes::Pipe', 'AWS::Scheduler::Schedule', 'AWS::Scheduler::ScheduleGroup', 'AWS::EventSchemas::Discoverer', 
                          'AWS::EventSchemas::Registry', 'AWS::EventSchemas::RegistryPolicy', 'AWS::EventSchemas::Schema', 'AWS::Evidently::Experiment', 
                          'AWS::Evidently::Feature', 'AWS::Evidently::Launch', 'AWS::Evidently::Project', 'AWS::Evidently::Segment', 'AWS::FinSpace::Environment', 
                          'AWS::FIS::ExperimentTemplate', 'AWS::FMS::NotificationChannel', 'AWS::FMS::Policy', 'AWS::FMS::ResourceSet', 'AWS::Forecast::Dataset', 
                          'AWS::Forecast::DatasetGroup', 'AWS::FraudDetector::Detector', 'AWS::FraudDetector::EntityType', 'AWS::FraudDetector::EventType', 
                          'AWS::FraudDetector::Label', 'AWS::FraudDetector::List', 'AWS::FraudDetector::Outcome', 'AWS::FraudDetector::Variable', 
                          'AWS::FSx::DataRepositoryAssociation', 'AWS::FSx::FileSystem', 'AWS::FSx::Snapshot', 'AWS::FSx::StorageVirtualMachine', 
                          'AWS::FSx::Volume', 'AWS::GameLift::Alias', 'AWS::GameLift::Build', 'AWS::GameLift::Fleet', 'AWS::GameLift::GameServerGroup', 
                          'AWS::GameLift::GameSessionQueue', 'AWS::GameLift::Location', 'AWS::GameLift::MatchmakingConfiguration', 
                          'AWS::GameLift::MatchmakingRuleSet', 'AWS::GameLift::Script', 'AWS::GlobalAccelerator::Accelerator', 
                          'AWS::GlobalAccelerator::EndpointGroup', 'AWS::GlobalAccelerator::Listener', 'AWS::Glue::Classifier', 'AWS::Glue::Connection', 
                          'AWS::Glue::Crawler', 'AWS::Glue::Database', 'AWS::Glue::DataCatalogEncryptionSettings', 'AWS::Glue::DataQualityRuleset', 
                          'AWS::Glue::DevEndpoint', 'AWS::Glue::Job', 'AWS::Glue::MLTransform', 'AWS::Glue::Partition', 'AWS::Glue::Registry', 
                          'AWS::Glue::Schema', 'AWS::Glue::SchemaVersion', 'AWS::Glue::SchemaVersionMetadata', 'AWS::Glue::SecurityConfiguration', 
                          'AWS::Glue::Table', 'AWS::Glue::Trigger', 'AWS::Glue::Workflow', 'AWS::Grafana::Workspace', 'AWS::GroundStation::Config', 
                          'AWS::GroundStation::DataflowEndpointGroup', 'AWS::GroundStation::MissionProfile', 'AWS::GuardDuty::Detector', 'AWS::GuardDuty::Filter', 
                          'AWS::GuardDuty::IPSet', 'AWS::GuardDuty::Master', 'AWS::GuardDuty::Member', 'AWS::GuardDuty::ThreatIntelSet', 'AWS::HealthLake::FHIRDatastore', 
                          'AWS::IAM::AccessKey', 'AWS::IAM::Group', 'AWS::IAM::GroupPolicy', 'AWS::IAM::InstanceProfile', 'AWS::IAM::ManagedPolicy', 
                          'AWS::IAM::OIDCProvider', 'AWS::IAM::Policy', 'AWS::IAM::Role', 'AWS::IAM::RolePolicy', 'AWS::IAM::SAMLProvider', 
                          'AWS::IAM::ServerCertificate', 'AWS::IAM::ServiceLinkedRole', 'AWS::IAM::User', 'AWS::IAM::UserPolicy', 'AWS::IAM::UserToGroupAddition', 
                          'AWS::IAM::VirtualMFADevice', 'AWS::IdentityStore::Group', 'AWS::IdentityStore::GroupMembership', 'AWS::AccessAnalyzer::Analyzer', 
                          'AWS::ImageBuilder::Component', 'AWS::ImageBuilder::ContainerRecipe', 'AWS::ImageBuilder::DistributionConfiguration', 
                          'AWS::ImageBuilder::Image', 'AWS::ImageBuilder::ImagePipeline', 'AWS::ImageBuilder::ImageRecipe', 
                          'AWS::ImageBuilder::InfrastructureConfiguration', 'AWS::SSMIncidents::ReplicationSet', 'AWS::SSMIncidents::ResponsePlan', 
                          'AWS::SSMContacts::Contact', 'AWS::SSMContacts::ContactChannel', 'AWS::SSMContacts::Plan', 'AWS::SSMContacts::Rotation', 
                          'AWS::Inspector::AssessmentTarget', 'AWS::Inspector::AssessmentTemplate', 'AWS::Inspector::ResourceGroup', 'AWS::InspectorV2::Filter', 
                          'AWS::InternetMonitor::Monitor', 'AWS::IoT::AccountAuditConfiguration', 'AWS::IoT::Authorizer', 'AWS::IoT::BillingGroup', 
                          'AWS::IoT::CACertificate', 'AWS::IoT::Certificate', 'AWS::IoT::CustomMetric', 'AWS::IoT::Dimension', 'AWS::IoT::DomainConfiguration', 
                          'AWS::IoT::FleetMetric', 'AWS::IoT::JobTemplate', 'AWS::IoT::Logging', 'AWS::IoT::MitigationAction', 'AWS::IoT::Policy', 
                          'AWS::IoT::PolicyPrincipalAttachment', 'AWS::IoT::ProvisioningTemplate', 'AWS::IoT::ResourceSpecificLogging', 'AWS::IoT::RoleAlias', 
                          'AWS::IoT::ScheduledAudit', 'AWS::IoT::SecurityProfile', 'AWS::IoT::Thing', 'AWS::IoT::ThingGroup', 'AWS::IoT::ThingPrincipalAttachment', 
                          'AWS::IoT::ThingType', 'AWS::IoT::TopicRule', 'AWS::IoT::TopicRuleDestination', 'AWS::IoT1Click::Device', 'AWS::IoT1Click::Placement', 
                          'AWS::IoT1Click::Project', 'AWS::IoTAnalytics::Channel', 'AWS::IoTAnalytics::Dataset', 'AWS::IoTAnalytics::Datastore', 
                          'AWS::IoTAnalytics::Pipeline', 'AWS::IoTCoreDeviceAdvisor::SuiteDefinition', 'AWS::IoTEvents::AlarmModel', 'AWS::IoTEvents::DetectorModel',
                          'AWS::IoTEvents::Input', 'AWS::IoTFleetHub::Application', 'AWS::IoTFleetWise::Campaign', 'AWS::IoTFleetWise::DecoderManifest',
                          'AWS::IoTFleetWise::Fleet', 'AWS::IoTFleetWise::ModelManifest', 'AWS::IoTFleetWise::SignalCatalog', 'AWS::IoTFleetWise::Vehicle',
                          'AWS::Greengrass::ConnectorDefinition', 'AWS::Greengrass::ConnectorDefinitionVersion', 'AWS::Greengrass::CoreDefinition', 'AWS::Greengrass::CoreDefinitionVersion',
                          'AWS::Greengrass::DeviceDefinition', 'AWS::Greengrass::DeviceDefinitionVersion', 'AWS::Greengrass::FunctionDefinition', 'AWS::Greengrass::FunctionDefinitionVersion',
                          'AWS::Greengrass::Group', 'AWS::Greengrass::GroupVersion', 'AWS::Greengrass::LoggerDefinition', 'AWS::Greengrass::LoggerDefinitionVersion',
                          'AWS::Greengrass::ResourceDefinition', 'AWS::Greengrass::ResourceDefinitionVersion', 'AWS::Greengrass::SubscriptionDefinition', 'AWS::Greengrass::SubscriptionDefinitionVersion',
                          'AWS::GreengrassV2::ComponentVersion', 'AWS::GreengrassV2::Deployment', 'AWS::IoTSiteWise::AccessPolicy', 'AWS::IoTSiteWise::Asset',
                          'AWS::IoTSiteWise::AssetModel', 'AWS::IoTSiteWise::Dashboard', 'AWS::IoTSiteWise::Gateway', 'AWS::IoTSiteWise::Portal',
                          'AWS::IoTSiteWise::Project', 'AWS::IoTTwinMaker::ComponentType', 'AWS::IoTTwinMaker::Entity', 'AWS::IoTTwinMaker::Scene',
                          'AWS::IoTTwinMaker::SyncJob', 'AWS::IoTTwinMaker::Workspace', 'AWS::IoTWireless::Destination', 'AWS::IoTWireless::DeviceProfile',
                          'AWS::IoTWireless::FuotaTask', 'AWS::IoTWireless::MulticastGroup', 'AWS::IoTWireless::NetworkAnalyzerConfiguration', 'AWS::IoTWireless::PartnerAccount',
                          'AWS::IoTWireless::ServiceProfile', 'AWS::IoTWireless::TaskDefinition', 'AWS::IoTWireless::WirelessDevice', 'AWS::IoTWireless::WirelessDeviceImportTask',
                          'AWS::IoTWireless::WirelessGateway', 'AWS::IVS::Channel', 'AWS::IVS::PlaybackKeyPair', 'AWS::IVS::RecordingConfiguration', 'AWS::IVS::StreamKey',
                          'AWS::IVSChat::LoggingConfiguration', 'AWS::IVSChat::Room', 'AWS::Kendra::DataSource', 'AWS::Kendra::Faq', 'AWS::Kendra::Index',
                          'AWS::KendraRanking::ExecutionPlan', 'AWS::Cassandra::Keyspace', 'AWS::Cassandra::Table', 'AWS::Kinesis::Stream', 'AWS::Kinesis::StreamConsumer',
                          'AWS::KinesisAnalytics::Application', 'AWS::KinesisAnalytics::ApplicationOutput', 'AWS::KinesisAnalytics::ApplicationReferenceDataSource', 'AWS::KinesisAnalyticsV2::Application',
                          'AWS::KinesisAnalyticsV2::ApplicationCloudWatchLoggingOption', 'AWS::KinesisAnalyticsV2::ApplicationOutput', 'AWS::KinesisAnalyticsV2::ApplicationReferenceDataSource', 'AWS::KinesisFirehose::DeliveryStream',
                          'AWS::KinesisVideo::SignalingChannel', 'AWS::KinesisVideo::Stream', 'AWS::KMS::Alias', 'AWS::KMS::Key', 'AWS::KMS::ReplicaKey',
                          'AWS::LakeFormation::DataCellsFilter', 'AWS::LakeFormation::DataLakeSettings', 'AWS::LakeFormation::Permissions', 'AWS::LakeFormation::PrincipalPermissions',
                          'AWS::LakeFormation::Resource', 'AWS::LakeFormation::Tag', 'AWS::LakeFormation::TagAssociation', 'AWS::Lambda::Alias', 'AWS::Lambda::CodeSigningConfig',
                          'AWS::Lambda::EventInvokeConfig', 'AWS::Lambda::EventSourceMapping', 'AWS::Lambda::Function', 'AWS::Lambda::LayerVersion', 'AWS::Lambda::LayerVersionPermission',
                          'AWS::Lambda::Permission', 'AWS::Lambda::Url', 'AWS::Lambda::Version', 'AWS::Lex::Bot', 'AWS::Lex::BotAlias', 'AWS::Lex::BotVersion',
                          'AWS::Lex::ResourcePolicy', 'AWS::LicenseManager::Grant', 'AWS::LicenseManager::License', 'AWS::Lightsail::Alarm', 'AWS::Lightsail::Bucket',
                          'AWS::Lightsail::Certificate', 'AWS::Lightsail::Container', 'AWS::Lightsail::Database', 'AWS::Lightsail::Disk', 'AWS::Lightsail::Distribution',
                          'AWS::Lightsail::Instance', 'AWS::Lightsail::LoadBalancer', 'AWS::Lightsail::LoadBalancerTlsCertificate', 'AWS::Lightsail::StaticIp', 'AWS::Location::GeofenceCollection',
                          'AWS::Location::Map', 'AWS::Location::PlaceIndex', 'AWS::Location::RouteCalculator', 'AWS::Location::Tracker', 'AWS::Location::TrackerConsumer',
                          'AWS::LookoutEquipment::InferenceScheduler', 'AWS::LookoutMetrics::Alert', 'AWS::LookoutMetrics::AnomalyDetector', 'AWS::LookoutVision::Project', 'AWS::M2::Application',
                          'AWS::M2::Environment', 'AWS::Macie::AllowList', 'AWS::Macie::CustomDataIdentifier', 'AWS::Macie::FindingsFilter', 'AWS::Macie::Session',
                          'AWS::ManagedBlockchain::Accessor', 'AWS::ManagedBlockchain::Member', 'AWS::ManagedBlockchain::Node', 'AWS::MediaConnect::Bridge', 'AWS::MediaConnect::BridgeOutput',
                          'AWS::MediaConnect::BridgeSource', 'AWS::MediaConnect::Flow', 'AWS::MediaConnect::FlowEntitlement', 'AWS::MediaConnect::FlowOutput', 'AWS::MediaConnect::FlowSource',
                          'AWS::MediaConnect::FlowVpcInterface', 'AWS::MediaConnect::Gateway', 'AWS::MediaConvert::JobTemplate', 'AWS::MediaConvert::Preset', 'AWS::MediaConvert::Queue',
                          'AWS::MediaLive::Channel', 'AWS::MediaLive::Input', 'AWS::MediaLive::InputSecurityGroup', 'AWS::MediaPackage::Asset', 'AWS::MediaPackage::Channel',
                          'AWS::MediaPackage::OriginEndpoint', 'AWS::MediaPackage::PackagingConfiguration', 'AWS::MediaPackage::PackagingGroup', 'AWS::MediaTailor::Channel', 'AWS::MediaTailor::ChannelPolicy',
                          'AWS::MediaTailor::LiveSource', 'AWS::MediaTailor::PlaybackConfiguration', 'AWS::MediaTailor::SourceLocation', 'AWS::MediaTailor::VodSource', 'AWS::MediaStore::Container',
                          'AWS::AmazonMQ::Broker', 'AWS::AmazonMQ::Configuration', 'AWS::AmazonMQ::ConfigurationAssociation', 'AWS::MemoryDB::ACL', 'AWS::MemoryDB::Cluster', 'AWS::MemoryDB::ParameterGroup',
                          'AWS::MemoryDB::SubnetGroup', 'AWS::MemoryDB::User', 'AWS::MSK::BatchScramSecret', 'AWS::MSK::Cluster', 'AWS::MSK::ClusterPolicy', 'AWS::MSK::Configuration',
                          'AWS::MSK::ServerlessCluster', 'AWS::MSK::VpcConnection', 'AWS::KafkaConnect::Connector', 'AWS::MWAA::Environment', 'AWS::Neptune::DBCluster', 'AWS::Neptune::DBClusterParameterGroup',
                          'AWS::Neptune::DBInstance', 'AWS::Neptune::DBParameterGroup', 'AWS::Neptune::DBSubnetGroup', 'AWS::NetworkFirewall::Firewall', 'AWS::NetworkFirewall::FirewallPolicy', 'AWS::NetworkFirewall::LoggingConfiguration',
                          'AWS::NetworkFirewall::RuleGroup', 'AWS::NetworkManager::ConnectAttachment', 'AWS::NetworkManager::ConnectPeer', 'AWS::NetworkManager::CoreNetwork', 'AWS::NetworkManager::CustomerGatewayAssociation',
                          'AWS::NetworkManager::Device', 'AWS::NetworkManager::GlobalNetwork', 'AWS::NetworkManager::Link', 'AWS::NetworkManager::LinkAssociation', 'AWS::NetworkManager::Site',
                          'AWS::NetworkManager::SiteToSiteVpnAttachment', 'AWS::NetworkManager::TransitGatewayPeering', 'AWS::NetworkManager::TransitGatewayRegistration', 'AWS::NetworkManager::TransitGatewayRouteTableAttachment', 'AWS::NetworkManager::VpcAttachment',
                          'AWS::NimbleStudio::LaunchProfile', 'AWS::NimbleStudio::StreamingImage', 'AWS::NimbleStudio::Studio', 'AWS::NimbleStudio::StudioComponent', 'AWS::Oam::Link',
                          'AWS::Oam::Sink', 'AWS::Omics::AnnotationStore', 'AWS::Omics::ReferenceStore', 'AWS::Omics::RunGroup', 'AWS::Omics::SequenceStore', 'AWS::Omics::VariantStore',
                          'AWS::Omics::Workflow', 'AWS::OSIS::Pipeline', 'AWS::OpenSearchService::Domain', 'AWS::Elasticsearch::Domain', 'AWS::OpenSearchServerless::AccessPolicy', 'AWS::OpenSearchServerless::Collection',
                          'AWS::OpenSearchServerless::SecurityConfig', 'AWS::OpenSearchServerless::SecurityPolicy', 'AWS::OpenSearchServerless::VpcEndpoint', 'AWS::OpsWorks::App', 'AWS::OpsWorks::ElasticLoadBalancerAttachment',
                          'AWS::OpsWorks::Instance', 'AWS::OpsWorks::Layer', 'AWS::OpsWorks::Stack', 'AWS::OpsWorks::UserProfile', 'AWS::OpsWorks::Volume', 'AWS::OpsWorksCM::Server',
                          'AWS::Organizations::Account', 'AWS::Organizations::Organization', 'AWS::Organizations::OrganizationalUnit', 'AWS::Organizations::Policy', 'AWS::Organizations::ResourcePolicy', 'AWS::Panorama::ApplicationInstance',
                          'AWS::Panorama::Package', 'AWS::Panorama::PackageVersion', 'AWS::Personalize::Dataset', 'AWS::Personalize::DatasetGroup', 'AWS::Personalize::Schema', 'AWS::Personalize::Solution',
                          'AWS::Pinpoint::ADMChannel', 'AWS::Pinpoint::APNSChannel', 'AWS::Pinpoint::APNSSandboxChannel', 'AWS::Pinpoint::APNSVoipChannel', 'AWS::Pinpoint::APNSVoipSandboxChannel', 'AWS::Pinpoint::App',
                          'AWS::Pinpoint::ApplicationSettings', 'AWS::Pinpoint::BaiduChannel', 'AWS::Pinpoint::Campaign', 'AWS::Pinpoint::EmailChannel', 'AWS::Pinpoint::EmailTemplate', 'AWS::Pinpoint::EventStream',
                          'AWS::Pinpoint::GCMChannel', 'AWS::Pinpoint::InAppTemplate', 'AWS::Pinpoint::PushTemplate', 'AWS::Pinpoint::Segment', 'AWS::Pinpoint::SMSChannel', 'AWS::Pinpoint::SmsTemplate',
                          'AWS::Pinpoint::VoiceChannel', 'AWS::PinpointEmail::ConfigurationSet', 'AWS::PinpointEmail::ConfigurationSetEventDestination', 'AWS::PinpointEmail::DedicatedIpPool', 'AWS::PinpointEmail::Identity', 'AWS::Proton::EnvironmentAccountConnection',
                          'AWS::Proton::EnvironmentTemplate', 'AWS::Proton::ServiceTemplate', 'AWS::APS::RuleGroupsNamespace', 'AWS::APS::Workspace', 'AWS::QLDB::Ledger', 'AWS::QLDB::Stream',
                          'AWS::QuickSight::Analysis', 'AWS::QuickSight::Dashboard', 'AWS::QuickSight::DataSet', 'AWS::QuickSight::DataSource', 'AWS::QuickSight::RefreshSchedule', 'AWS::QuickSight::Template',
                          'AWS::QuickSight::Theme', 'AWS::QuickSight::Topic', 'AWS::QuickSight::VPCConnection', 'AWS::RAM::Permission', 'AWS::RAM::ResourceShare', 'AWS::RDS::CustomDBEngineVersion',
                          'AWS::RDS::DBCluster', 'AWS::RDS::DBClusterParameterGroup', 'AWS::RDS::DBInstance', 'AWS::RDS::DBParameterGroup', 'AWS::RDS::DBProxy', 'AWS::RDS::DBProxyEndpoint',
                          'AWS::RDS::DBProxyTargetGroup', 'AWS::RDS::DBSecurityGroup', 'AWS::RDS::DBSecurityGroupIngress', 'AWS::RDS::DBSubnetGroup', 'AWS::RDS::EventSubscription', 'AWS::RDS::GlobalCluster',
                          'AWS::RDS::OptionGroup', 'AWS::Redshift::Cluster', 'AWS::Redshift::ClusterParameterGroup', 'AWS::Redshift::ClusterSecurityGroup', 'AWS::Redshift::ClusterSecurityGroupIngress', 'AWS::Redshift::ClusterSubnetGroup',
                          'AWS::Redshift::EndpointAccess', 'AWS::Redshift::EndpointAuthorization', 'AWS::Redshift::EventSubscription', 'AWS::Redshift::ScheduledAction', 'AWS::RedshiftServerless::Namespace', 'AWS::RedshiftServerless::Workgroup',
                          'AWS::RefactorSpaces::Application', 'AWS::RefactorSpaces::Environment', 'AWS::RefactorSpaces::Route', 'AWS::RefactorSpaces::Service', 'AWS::Rekognition::Collection', 'AWS::Rekognition::Project',
                          'AWS::Rekognition::StreamProcessor', 'AWS::ResilienceHub::App', 'AWS::ResilienceHub::ResiliencyPolicy', 'AWS::ResourceExplorer2::DefaultViewAssociation', 'AWS::ResourceExplorer2::Index', 'AWS::ResourceExplorer2::View',
                          'AWS::ResourceGroups::Group', 'AWS::RoboMaker::Fleet', 'AWS::RoboMaker::Robot', 'AWS::RoboMaker::RobotApplication', 'AWS::RoboMaker::RobotApplicationVersion', 'AWS::RoboMaker::SimulationApplication',
                          'AWS::RoboMaker::SimulationApplicationVersion', 'AWS::RolesAnywhere::CRL', 'AWS::RolesAnywhere::Profile', 'AWS::RolesAnywhere::TrustAnchor', 'AWS::Route53::CidrCollection', 'AWS::Route53::DNSSEC',
                          'AWS::Route53::HealthCheck', 'AWS::Route53::HostedZone', 'AWS::Route53::KeySigningKey', 'AWS::Route53::RecordSet', 'AWS::Route53::RecordSetGroup', 'AWS::Route53RecoveryControl::Cluster',
                          'AWS::Route53RecoveryControl::ControlPanel', 'AWS::Route53RecoveryControl::RoutingControl', 'AWS::Route53RecoveryControl::SafetyRule', 'AWS::Route53RecoveryReadiness::Cell', 'AWS::Route53RecoveryReadiness::ReadinessCheck', 'AWS::Route53RecoveryReadiness::RecoveryGroup',
                          'AWS::Route53RecoveryReadiness::ResourceSet', 'AWS::Route53Resolver::FirewallDomainList', 'AWS::Route53Resolver::FirewallRuleGroup', 'AWS::Route53Resolver::FirewallRuleGroupAssociation', 'AWS::Route53Resolver::OutpostResolver', 'AWS::Route53Resolver::ResolverConfig',
                          'AWS::Route53Resolver::ResolverDNSSECConfig', 'AWS::Route53Resolver::ResolverEndpoint', 'AWS::Route53Resolver::ResolverQueryLoggingConfig', 'AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation', 'AWS::Route53Resolver::ResolverRule', 'AWS::Route53Resolver::ResolverRuleAssociation',
                          'AWS::RUM::AppMonitor', 'AWS::S3::AccessPoint', 'AWS::S3::Bucket', 'AWS::S3::BucketPolicy', 'AWS::S3::MultiRegionAccessPoint', 'AWS::S3::MultiRegionAccessPointPolicy',
                          'AWS::S3::StorageLens', 'AWS::S3ObjectLambda::AccessPoint', 'AWS::S3ObjectLambda::AccessPointPolicy', 'AWS::S3Outposts::AccessPoint', 'AWS::S3Outposts::Bucket', 'AWS::S3Outposts::BucketPolicy',
                          'AWS::S3Outposts::Endpoint', 'AWS::SageMaker::App', 'AWS::SageMaker::AppImageConfig', 'AWS::SageMaker::CodeRepository', 'AWS::SageMaker::DataQualityJobDefinition', 'AWS::SageMaker::Device',
                          'AWS::SageMaker::DeviceFleet', 'AWS::SageMaker::Domain', 'AWS::SageMaker::Endpoint', 'AWS::SageMaker::EndpointConfig', 'AWS::SageMaker::FeatureGroup', 'AWS::SageMaker::Image',
                          'AWS::SageMaker::ImageVersion', 'AWS::SageMaker::InferenceExperiment', 'AWS::SageMaker::Model', 'AWS::SageMaker::ModelBiasJobDefinition', 'AWS::SageMaker::ModelCard', 'AWS::SageMaker::ModelExplainabilityJobDefinition',
                          'AWS::SageMaker::ModelPackage', 'AWS::SageMaker::ModelPackageGroup', 'AWS::SageMaker::ModelQualityJobDefinition', 'AWS::SageMaker::MonitoringSchedule', 'AWS::SageMaker::NotebookInstance', 'AWS::SageMaker::NotebookInstanceLifecycleConfig',
                          'AWS::SageMaker::Pipeline', 'AWS::SageMaker::Project', 'AWS::SageMaker::Space', 'AWS::SageMaker::UserProfile', 'AWS::SageMaker::Workteam', 'AWS::SecretsManager::ResourcePolicy',
                          'AWS::SecretsManager::RotationSchedule', 'AWS::SecretsManager::Secret', 'AWS::SecretsManager::SecretTargetAttachment', 'AWS::ServiceCatalog::AcceptedPortfolioShare', 'AWS::ServiceCatalog::CloudFormationProduct', 'AWS::ServiceCatalog::CloudFormationProvisionedProduct',
                          'AWS::ServiceCatalog::LaunchNotificationConstraint', 'AWS::ServiceCatalog::LaunchRoleConstraint', 'AWS::ServiceCatalog::LaunchTemplateConstraint', 'AWS::ServiceCatalog::Portfolio', 'AWS::ServiceCatalog::PortfolioPrincipalAssociation', 'AWS::ServiceCatalog::PortfolioProductAssociation',
                          'AWS::ServiceCatalog::PortfolioShare', 'AWS::ServiceCatalog::ResourceUpdateConstraint', 'AWS::ServiceCatalog::ServiceAction', 'AWS::ServiceCatalog::ServiceActionAssociation', 'AWS::ServiceCatalog::StackSetConstraint', 'AWS::ServiceCatalog::TagOption',
                          'AWS::ServiceCatalog::TagOptionAssociation', 'AWS::ServiceCatalogAppRegistry::Application', 'AWS::ServiceCatalogAppRegistry::AttributeGroup', 'AWS::ServiceCatalogAppRegistry::AttributeGroupAssociation', 'AWS::ServiceCatalogAppRegistry::ResourceAssociation', 'AWS::SecurityHub::AutomationRule',
                          'AWS::SecurityHub::Hub', 'AWS::SecurityHub::Standard', 'AWS::SES::ConfigurationSet', 'AWS::SES::ConfigurationSetEventDestination', 'AWS::SES::ContactList', 'AWS::SES::DedicatedIpPool',
                          'AWS::SES::EmailIdentity', 'AWS::SES::ReceiptFilter', 'AWS::SES::ReceiptRule', 'AWS::SES::ReceiptRuleSet', 'AWS::SES::Template', 'AWS::SES::VdmAttributes',
                          'AWS::SDB::Domain', 'AWS::Shield::DRTAccess', 'AWS::Shield::ProactiveEngagement', 'AWS::Shield::Protection', 'AWS::Shield::ProtectionGroup', 'AWS::Signer::ProfilePermission',
                          'AWS::Signer::SigningProfile', 'AWS::SimSpaceWeaver::Simulation', 'AWS::SNS::Subscription', 'AWS::SNS::Topic', 'AWS::SNS::TopicInlinePolicy', 'AWS::SNS::TopicPolicy',
                          'AWS::SQS::Queue', 'AWS::SQS::QueueInlinePolicy', 'AWS::SSM::Activation', 'AWS::SSM::Association', 'AWS::SSM::AssociationCompliance', 'AWS::SSM::Document', 'AWS::SSM::MaintenanceWindow',
                          'AWS::SSM::MaintenanceWindowTarget', 'AWS::SSM::MaintenanceWindowTask', 'AWS::SSM::OpsItem', 'AWS::SSM::OpsMetadata', 'AWS::SSM::Parameter', 'AWS::SSM::PatchBaseline',
                          'AWS::SSM::ResourceDataSync', 'AWS::SSM::ResourceDataSyncPreferences', 'AWS::SSO::Assignment', 'AWS::SSO::PermissionSet', 'AWS::SSO::ProvisioningRole', 'AWS::StepFunctions::Activity',
                          'AWS::StepFunctions::StateMachine', 'AWS::Synthetics::Canary', 'AWS::Synthetics::CanaryRun', 'AWS::Timestream::Database', 'AWS::Timestream::Table', 'AWS::Timestream::TablePolicy',
                          'AWS::Transfer::Server', 'AWS::Transfer::User', 'AWS::Transcribe::LanguageModel', 'AWS::Transcribe::MedicalLanguageModel', 'AWS::Transcribe::Vocabulary', 'AWS::Transcribe::VocabularyFilter',
                          'AWS::Translate::ParallelData', 'AWS::Translate::Terminology', 'AWS::WAF::ByteMatchSet', 'AWS::WAF::IPSet', 'AWS::WAF::RateBasedRule', 'AWS::WAF::RegexMatchSet',
                          'AWS::WAF::RegexPatternSet', 'AWS::WAF::Rule', 'AWS::WAF::RuleGroup', 'AWS::WAF::SizeConstraintSet', 'AWS::WAF::SqlInjectionMatchSet', 'AWS::WAF::WebACL',
                          'AWS::WAF::WebACLAssociation', 'AWS::WAF::XssMatchSet', 'AWS::WAFRegional::ByteMatchSet', 'AWS::WAFRegional::GeoMatchSet', 'AWS::WAFRegional::IPSet', 'AWS::WAFRegional::RateBasedRule',
                          'AWS::WAFRegional::RegexMatchSet', 'AWS::WAFRegional::RegexPatternSet', 'AWS::WAFRegional::Rule', 'AWS::WAFRegional::RuleGroup', 'AWS::WAFRegional::SizeConstraintSet', 'AWS::WAFRegional::SqlInjectionMatchSet',
                          'AWS::WAFRegional::WebACL', 'AWS::WAFRegional::WebACLAssociation', 'AWS::WAFRegional::XssMatchSet', 'AWS::WAFv2::IPSet', 'AWS::WAFv2::RegexPatternSet', 'AWS::WAFv2::RuleGroup',
                          'AWS::WAFv2::WebACL', 'AWS::WAFv2::WebACLAssociation', 'AWS::WellArchitected::Workload', 'AWS::WorkLink::Fleet', 'AWS::WorkLink::WebsiteCertificateAuthorityAssociation', 'AWS::WorkMail::Alias',
                          'AWS::WorkMail::Group', 'AWS::WorkMail::Mailbox', 'AWS::WorkMail::Organization', 'AWS::WorkMail::Resource', 'AWS::WorkMail::User', 'AWS::WorkSpaces::ConnectionAlias',
                          'AWS::WorkSpaces::IpGroup', 'AWS::WorkSpaces::Workspace', 'AWS::WorkSpaces::WorkspaceBundle', 'AWS::WorkSpaces::WorkspaceDirectory', 'AWS::WorkSpaces::WorkspaceImage', 'AWS::WorkSpaces::WorkspaceRoute',
                          'AWS::XRay::Group', 'AWS::XRay::SamplingRule', 'AWS::XRay::ResourcePolicy', 'AWS::XRay::Token']

def cf_validator_path(path):

    start=len(path)-4
    end=len(path)

    if path[start:end] in ['json','yaml','.yml']:
        file=path[start:end]
        extension=True

    else:
        print('Error: The provided input file format is not valid.')
        extension=False

    if extension==True:

        if file_size_path(path)>1000000:
            print("Error: The size of the input file exceeds 1MB.")
            sys.exit()

        else:           
            if file=='json':
                f=open(path)
                json_data=f.read()
                val=is_valid_json(json_data)
                
                if val[0]==False:
                    print(val[1])
                    sys.exit()
                
                else:
                    data=json.loads(json_data)
                    key_list=list(data.keys())
                    ref_values=extract_ref_values_json(data)
                    
                    resources=data.get("Resources",{})

                    for resource_name, resource_properties in resources.items():
                        if "Type" in resource_properties:
                            resource_type = resource_properties["Type"]
                            resource_types.append(resource_type)
                        else:
                            print(f"Error: The resource named '{resource_name}' lacks the required 'Type' value.")
                            sys.exit()

                    l=resources.keys() 

                    if len(l)>500:
                        print("Error: The number of resources", len(l), "exceeds the allowable maximum of 500.")
                        sys.exit()

                    for resource_name, resource_properties in resources.items():
                        dependencies = extract_depends_on(resource_properties)
                        all_depends_on.extend(dependencies)

                    for i in all_depends_on:
                        if type(i)==str:
                            continue
                        else:
                            print("Error: The dependency for", i, "must be specified as a string.")
                            sys.exit()

                    for i in l:
                        checklist.append(i)

                    parameters=data.get("Parameters",{})
                    m=parameters.keys()

                    for i in m:
                        checklist.append(i)

                    types=parameters.values()

                    for parameter_name, parameter_properties in parameters.items():
                        if "Type" in parameter_properties:
                            parameter_type = parameter_properties["Type"]
                            parameter_types.append(parameter_type)
                        else:
                            print(f"Error: The parameter '{parameter_name}' does not have the required 'Type' value.")
                            sys.exit()
                            
                    if 'Resources' in key_list:
                        for i in key_list:
                            if i=='AWSTemplateFormatVersion':
                                if type(data['AWSTemplateFormatVersion'])==str:
                                    continue
                                else:
                                    print("Error: The value of 'AWSTemplateFormatVersion' should be a string representing a valid date.")
                                    sys.exit()

                            elif i=='Description':
                                if type(data['Description'])==str:
                                    continue
                                else:
                                    print("Error: The 'Description' field should be of type string.")
                                    sys.exit()

                            elif i=='Metadata':
                                continue

                            elif i=='Resources':                    
                                for k in ref_values:
                                    if k in checklist:
                                        continue
                                    else:
                                        if k in ['AWS::StackId', 'AWS::Region', 'AWS::StackName']:
                                            continue
                                        else:
                                            print("Error: The reference to", k,"is not present.")
                                            sys.exit()

                                for k in all_depends_on:
                                    if k in checklist:
                                        continue
                                    else:
                                        print("Error:", k, "is absent, yet it is being depended upon by other resources.")
                                        sys.exit()

                                for k in resource_types:
                                    if k in valid_aws_resource_types:
                                        continue
                                    else:
                                        print("Error:", k, "is not a valid resource type.")
                                        sys.exit()

                            elif i=='Parameters':
                                for i in parameter_types:
                                    if i in ['String', 'Number', 'List<Number>', 'CommaDelimitedList']:
                                        continue
                                    else:
                                        if i[:3]=='AWS':
                                            continue
                                        else:
                                            print("Error: The 'Type' specified in the 'Parameters' section is invalid.")
                                            sys.exit()
                                
                                has_intrinsic_in_params = has_intrinsic_functions_in_parameters(data)

                                if has_intrinsic_in_params:
                                    print("Error: The 'Parameters' dictionary includes intrinsic functions.")
                                    sys.exit()

                                else:
                                    continue

                            elif i=='Rules':
                                continue

                            elif i=='Mappings':
                                continue

                            elif i=='Conditions':
                                continue
                            
                            elif i=='Transform':
                                continue
                                            
                            elif i=='Outputs':
                                continue
                            
                            else:
                                print("Error: Unrecognized data", i, "encountered.")
                                sys.exit()

                    else:
                        print("Error: Resource data is absent within the file.")
                        sys.exit()

                    print("Validation successful, the input file is valid.")
            

            else:

                f=open(path)  
                if is_valid_yaml(path)==True:
                    read=f.read()
                    l=read.split("!")
                    read_data=""
                    for i in l:
                        read_data+=i+"s!"
                    read_data=read_data[:-2]
                    input_dict=yaml.safe_load(read_data) 
                    modified_dict = replace_s_exclamation(input_dict)
                    
                    key_list=list(modified_dict.keys())
                    ref_values=extract_ref_values_yaml(modified_dict)
                    
                    resources=modified_dict.get("Resources",{})

                    for resource_name, resource_properties in resources.items():
                        if "Type" in resource_properties:
                            resource_type = resource_properties["Type"]
                            resource_types.append(resource_type)
                        else:
                            print(f"Error: The resource '{resource_name}' does not have the required 'Type' value.")
                            sys.exit()

                    l=resources.keys() 

                    if len(l)>500:
                        print("Error: The count of resources", len(l), "surpasses the maximum allowable limit of 500.")
                        sys.exit()

                    for resource_name, resource_properties in resources.items():
                        dependencies = extract_depends_on(resource_properties)
                        all_depends_on.extend(dependencies)

                    for i in all_depends_on:
                        if type(i)==str:
                            continue
                        else:
                            print("Error: The dependency for", i, "should be specified as a string.") 
                            sys.exit()   

                    for i in l:
                        checklist.append(i)

                    parameters=modified_dict.get("Parameters",{})
                    m=parameters.keys()

                    for i in m:
                        checklist.append(i)

                    types=parameters.values()

                    for parameter_name, parameter_properties in parameters.items():
                        if "Type" in parameter_properties:
                            parameter_type = parameter_properties["Type"]
                            parameter_types.append(parameter_type)
                        else:
                            print(f"Error: The parameter '{parameter_name}' lacks the required 'Type' value.")
                            sys.exit()
                    
                    if 'Resources' in key_list:
                        for i in key_list:
                            if i=='AWSTemplateFormatVersion':
                                if type(modified_dict['AWSTemplateFormatVersion'])==str:
                                    continue
                                else:
                                    print("Error: The 'AWSTemplateFormatVersion' should be a string containing a valid date.")
                                    sys.exit()

                            elif i=='Description':
                                if type(modified_dict['Description'])==str:
                                    continue
                                else:
                                    print("Error: The 'Description' field should be of string type.")
                                    sys.exit()

                            elif i=='Metadata':
                                continue

                            elif i=='Resources':                    
                                for k in ref_values:
                                    if k in checklist:
                                        continue
                                    else:
                                        print("Error: The reference", k, "is not present.")
                                        sys.exit()

                                for k in all_depends_on:
                                    if k in checklist:
                                        continue
                                    else:
                                        print("Error:", k, "is not present but is being depended upon by other resources.")
                                        sys.exit()

                                for k in resource_types:
                                    if k in valid_aws_resource_types:
                                        continue
                                    else:
                                        print("Error:",k,"is not a valid resource type.")
                                        sys.exit()

                            elif i=='Parameters':
                                for i in parameter_types:
                                    if i in ['String', 'Number', 'List<Number>', 'CommaDelimitedList']:
                                        continue
                                    else:
                                        print("Error: The 'Type' specified in the 'Parameters' is invalid.")
                                        sys.exit()
                                
                                has_intrinsic_in_params = has_intrinsic_functions_in_parameters(modified_dict)

                                if has_intrinsic_in_params:
                                    print("Error: The 'Parameters' dictionary contains intrinsic functions.")
                                    sys.exit()

                                else:
                                    continue

                            elif i=='Rules':
                                continue

                            elif i=='Mappings':
                                continue

                            elif i=='Conditions':
                                continue
                            
                            elif i=='Transform':
                                continue
                                            
                            elif i=='Outputs':
                                continue
                            
                            else:
                                print("Error: Unrecognized data", i, "encountered.")
                                sys.exit()

                    else:
                        print("Error: The file lacks resource data.")
                        sys.exit()

                    print("Validation successful, the input file is valid.")

                else:
                    print(is_valid_yaml(path))
                    sys.exit()

def cf_validator_url(url):

    read = get_url_contents(url)
        
    if read:

        if file_size_url(url)>1000000:
            print("Error: The file size exceeds 1MB.")
            sys.exit()

        else:
            if '{' in read:
                
                val=is_valid_json(read)
                
                if val[0]==False:
                    print(val[1])
                    sys.exit()
                
                else:
                    data=json.loads(read)
                    key_list=list(data.keys())
                    ref_values=extract_ref_values_json(data)
                    
                    resources=data.get("Resources",{})

                    for resource_name, resource_properties in resources.items():
                        if "Type" in resource_properties:
                            resource_type = resource_properties["Type"]
                            resource_types.append(resource_type)
                        else:
                            print(f"Error: The resource '{resource_name}' lacks the required 'Type' value.")
                            sys.exit()

                    l=resources.keys()

                    if len(l)>500:
                        print("Error: The count of resources", len(l), "exceeds the maximum allowable limit of 500.")
                        sys.exit()
    
                    for resource_name, resource_properties in resources.items():
                        dependencies = extract_depends_on(resource_properties)
                        all_depends_on.extend(dependencies) 

                    for i in l:
                        checklist.append(i)

                    parameters=data.get("Parameters",{})
                    m=parameters.keys()

                    for i in all_depends_on:
                        if type(i)==str:
                            continue
                        else:
                            print("Error: The dependency for", i, "must be specified as a string.")
                            sys.exit()

                    for i in m:
                        checklist.append(i)

                    types=parameters.values()
                    
                    for parameter_name, parameter_properties in parameters.items():
                        if "Type" in parameter_properties:
                            parameter_type = parameter_properties["Type"]
                            parameter_types.append(parameter_type)
                        else:
                            print(f"Error: The parameter '{parameter_name}' is missing the required 'Type' value.")
                            sys.exit()
                            
                    if 'Resources' in key_list:
                        for i in key_list:
                            if i=='AWSTemplateFormatVersion':
                                if type(data['AWSTemplateFormatVersion'])==str:
                                    continue
                                else:
                                    print("Error: The 'AWSTemplateFormatVersion' should be a string containing a valid date.")
                                    sys.exit()

                            elif i=='Description':
                                if type(data['Description'])==str:
                                    continue
                                else:
                                    print("Error: The 'Description' field should be of type string.")
                                    sys.exit()

                            elif i=='Metadata':
                                continue

                            elif i=='Resources':                    
                                for k in ref_values:
                                    if k in checklist:
                                        continue
                                    else:
                                        if k in ['AWS::StackId', 'AWS::Region', 'AWS::StackName']:
                                            continue
                                        else:
                                            print("Error: The reference", k, "is not present.")
                                            sys.exit()
                                
                                for k in all_depends_on:
                                    if k in checklist:
                                        continue
                                    else:
                                        print("Error:",k,"is not present, yet it is being depended upon by other resources.")
                                        sys.exit()

                                for k in resource_types:
                                    if k in valid_aws_resource_types:
                                        continue
                                    else:
                                        print("Error:",k,"is not a valid resource type.")
                                        sys.exit()

                            elif i=='Parameters':
                                for i in parameter_types:
                                    if i in ['String', 'Number', 'List<Number>', 'CommaDelimitedList']:
                                        continue
                                    else:
                                        if i[:3]=='AWS':
                                            continue
                                        else:
                                            print("Error: The 'Type' specified in the 'Parameters' section is invalid.")
                                            sys.exit()
                                
                                has_intrinsic_in_params = has_intrinsic_functions_in_parameters(data)

                                if has_intrinsic_in_params:
                                    print("Error: The 'Parameters' dictionary contains intrinsic functions.")
                                    sys.exit()

                                else:
                                    continue

                            elif i=='Rules':
                                continue

                            elif i=='Mappings':
                                continue

                            elif i=='Conditions':
                                continue
                            
                            elif i=='Transform':
                                continue
                                            
                            elif i=='Outputs':
                                continue
                            
                            else:
                                print("Error: Unrecognized data", i, "encountered.")
                                sys.exit()

                    else:
                        print("Error: The resource data is missing in the file.")
                        sys.exit()

                    print("Validation successful, the input file is valid.")

            else:
                if is_valid_yaml(read)==True:
                    l=read.split("!")
                    read_data=""
                    for i in l:
                        read_data+=i+"s!"
                    read_data=read_data[:-2]
                    input_dict=yaml.safe_load(read_data) 
                    modified_dict = replace_s_exclamation(input_dict)
                    
                    key_list=list(modified_dict.keys())
                    ref_values=extract_ref_values_yaml(modified_dict)
                    
                    resources=modified_dict.get("Resources",{})

                    for resource_name, resource_properties in resources.items():
                        if "Type" in resource_properties:
                            resource_type = resource_properties["Type"]
                            resource_types.append(resource_type)
                        else:
                            print(f"Error: The resource '{resource_name}' does not possess the required 'Type' value.")
                            sys.exit()

                    l=resources.keys()

                    if len(l)>500:
                        print("Error: The quantity of resources", len(l), "exceeds the maximum allowable limit of 500.")
                        sys.exit()      

                    for resource_name, resource_properties in resources.items():
                        dependencies = extract_depends_on(resource_properties)
                        all_depends_on.extend(dependencies) 

                    for i in all_depends_on:
                        if type(i)==str:
                            continue
                        else:
                            print("Error: The dependency for", i, "must be expressed as a string.")
                            sys.exit()

                    for i in l:
                        checklist.append(i)

                    parameters=modified_dict.get("Parameters",{})
                    m=parameters.keys()

                    for i in m:
                        checklist.append(i)

                    types=parameters.values()

                    for parameter_name, parameter_properties in parameters.items():
                        if "Type" in parameter_properties:
                            parameter_type = parameter_properties["Type"]
                            parameter_types.append(parameter_type)
                        else:
                            print(f"Error: The parameter '{parameter_name}' lacks the mandatory 'Type' value.")
                            sys.exit()
                    
                    if 'Resources' in key_list:
                        for i in key_list:
                            if i=='AWSTemplateFormatVersion':
                                if type(modified_dict['AWSTemplateFormatVersion'])==str:
                                    continue
                                else:
                                    print("Error: The 'AWSTemplateFormatVersion' should be presented as a string containing a valid date.")
                                    sys.exit()

                            elif i=='Description':
                                if type(modified_dict['Description'])==str:
                                    continue
                                else:
                                    print("Error: The 'Description' field should be in the form of a string.")
                                    sys.exit()

                            elif i=='Metadata':
                                continue

                            elif i=='Resources':                    
                                for k in ref_values:
                                    if k in checklist:
                                        continue
                                    else:
                                        print("Error: The reference", k, "is absent.")
                                        sys.exit()

                                for k in all_depends_on:
                                    if k in checklist:
                                        continue
                                    else:
                                        print("Error:", k, "is not present but is being relied upon by other resources.")
                                        sys.exit()

                                for k in resource_types:
                                    if k in valid_aws_resource_types:
                                        continue
                                    else:
                                        print("Error:", k, "is not a valid resource type.")
                                        sys.exit()

                            elif i=='Parameters':
                                for i in parameter_types:
                                    if i in ['String', 'Number', 'List<Number>', 'CommaDelimitedList']:
                                        continue
                                    else:
                                        print("Error: The 'Type' specified in the 'Parameters' is invalid.")
                                        sys.exit()
                                
                                has_intrinsic_in_params = has_intrinsic_functions_in_parameters(modified_dict)

                                if has_intrinsic_in_params:
                                    print("Error: The 'Parameters' dictionary contains intrinsic functions.")
                                    sys.exit()

                                else:
                                    continue

                            elif i=='Rules':
                                continue

                            elif i=='Mappings':
                                continue

                            elif i=='Conditions':
                                continue
                            
                            elif i=='Transform':
                                continue
                                            
                            elif i=='Outputs':
                                continue
                            
                            else:
                                print("Error: Unidentified data", i, "encountered.")
                                sys.exit()

                    else:
                        print("Error: The resource data is absent in the file.")
                        sys.exit()

                    print("Validation successful, the input file is valid.")

                else:
                    print(is_valid_yaml(read))
                    sys.exit()     
