import argparse
import boto3
import botocore
import csv
import sys
import json
import requests
from botocore.auth import SigV4Auth
import requests
from botocore.awsrequest import AWSRequest
import botocore.session
import json

def boto3_paginate(client, method, *args, _page_key=None, **kwargs):
    if _page_key is None:
        api_method = client.meta.method_to_api_mapping[method]
        api_model = client.meta.service_model.operation_model(api_method)

        list_member_key = None

        for key, value in api_model.output_shape.members.items():
            if value.type_name == 'list':
                if list_member_key:
                    raise Exception(f'Found multiple list members for {method}')
                list_member_key = key

        if not list_member_key:
            raise Exception(f'Could not find list member key for {method}')

        _page_key = list_member_key

    paginator = client.get_paginator(method)
    page_iterator = paginator.paginate(*args, **kwargs)
    for page in page_iterator:
        yield from page[_page_key]


def account_assignments(args):
    organizations = boto3.client('organizations')
    accounts = boto3_paginate(organizations, 'list_accounts')

    sso_admin = boto3.client('sso-admin')
    sso_instance = list(boto3_paginate(sso_admin, 'list_instances'))[0]
    sso_instance_arn = sso_instance['InstanceArn']
    sso_instance_identity_store_id = sso_instance['IdentityStoreId']

    identitystore = boto3.client('identitystore')
    users = boto3_paginate(identitystore, 'list_users', IdentityStoreId=sso_instance_identity_store_id)
    users = {user['UserId']: user['Emails'][0]['Value'] for user in users}

    groups = boto3_paginate(identitystore, 'list_groups', IdentityStoreId=sso_instance_identity_store_id)
    groups = {group['GroupId']: group['DisplayName'] for group in groups}

    permissions_sets = {}
    for permission_set_arn in boto3_paginate(sso_admin, 'list_permission_sets', InstanceArn=sso_instance_arn):
        permission_set_name = sso_admin.describe_permission_set(InstanceArn=sso_instance_arn, PermissionSetArn=permission_set_arn)['PermissionSet']['Name']
        permissions_sets[permission_set_arn] = permission_set_name

    csv_output = [['Account ID', 'Account Name', 'Permission Set ARN', 'Permission Set Name', 'Principal Type', 'Principal ID', 'Principal Name']]

    for account in accounts:
        account_id = account['Id']
        account_name = account['Name']

        permissions_set_arns = boto3_paginate(sso_admin, 'list_permission_sets_provisioned_to_account', InstanceArn=sso_instance_arn, AccountId=account_id)

        for permission_set_arn in permissions_set_arns:
            permission_set_name = permissions_sets[permission_set_arn]

            permission_set_users = boto3_paginate(sso_admin, 'list_account_assignments', InstanceArn=sso_instance_arn, AccountId=account_id, PermissionSetArn=permission_set_arn)
            for permission_set_user in permission_set_users:
                principal_type = permission_set_user['PrincipalType']
                principal_id = permission_set_user['PrincipalId']

                if principal_type == 'USER':
                    principal_name = users[principal_id]
                elif principal_type == 'GROUP':
                    principal_name = groups[principal_id]

                csv_output.append([account_id, account_name, permission_set_arn, permission_set_name, principal_type, principal_id, principal_name])

    # Use Python's csv module to print the CSV output
    csv_writer = csv.writer(sys.stdout)
    csv_writer.writerows(csv_output)


def user_group_assignments(args):
    sso_admin = boto3.client('sso-admin')
    sso_instance = list(boto3_paginate(sso_admin, 'list_instances'))[0]
    sso_instance_arn = sso_instance['InstanceArn']
    sso_instance_identity_store_id = sso_instance['IdentityStoreId']

    identitystore = boto3.client('identitystore')
    users = boto3_paginate(identitystore, 'list_users', IdentityStoreId=sso_instance_identity_store_id)
    users = {user['UserId']: user['Emails'][0]['Value'] for user in users}

    groups = boto3_paginate(identitystore, 'list_groups', IdentityStoreId=sso_instance_identity_store_id)
    groups = {group['GroupId']: group['DisplayName'] for group in groups}

    csv_output = [['Group ID', 'Group Name', 'User ID', 'User Name']]

    for group_id, group_name in groups.items():
        group_users = boto3_paginate(identitystore, 'list_group_memberships', IdentityStoreId=sso_instance_identity_store_id, GroupId=group_id)
        for group_user in group_users:
            user_id = group_user['MemberId']['UserId']
            user_name = users[user_id]

            csv_output.append([group_id, group_name, user_id, user_name])

    # Use Python's csv module to print the CSV output
    csv_writer = csv.writer(sys.stdout)
    csv_writer.writerows(csv_output)

def pretty_json(input_json_string):
    if not input_json_string:
        return ''
    return json.dumps(json.loads(input_json_string), indent=4, sort_keys=True)


def permissions_sets(args):
    sso_admin = boto3.client('sso-admin')
    sso_instance = list(boto3_paginate(sso_admin, 'list_instances'))[0]
    sso_instance_arn = sso_instance['InstanceArn']
    sso_instance_identity_store_id = sso_instance['IdentityStoreId']

    permission_sets = boto3_paginate(sso_admin, 'list_permission_sets', InstanceArn=sso_instance_arn)
    csv_output = [['ARN', 'Name', 'Description', 'Created Date', 'Inline Policy', 'Managed Policies']]

    for permission_set_arn in permission_sets:
        permission_set = sso_admin.describe_permission_set(InstanceArn=sso_instance_arn, PermissionSetArn=permission_set_arn)['PermissionSet']
        permission_set_name = permission_set['Name']
        permission_set_description = permission_set.get('Description') or ''
        permission_set_created_date = permission_set['CreatedDate']
        permission_set_inline_policy = sso_admin.get_inline_policy_for_permission_set(InstanceArn=sso_instance_arn, PermissionSetArn=permission_set_arn)['InlinePolicy']
        permission_set_managed_policies = boto3_paginate(sso_admin, 'list_managed_policies_in_permission_set', InstanceArn=sso_instance_arn, PermissionSetArn=permission_set_arn)
        permission_set_managed_policy_names = [managed_policy['Name'] for managed_policy in permission_set_managed_policies]

        csv_output.append([permission_set_arn, permission_set_name, permission_set_description, permission_set_created_date, pretty_json(permission_set_inline_policy), '\n'.join(permission_set_managed_policy_names)])

    # Use Python's csv module to print the CSV output
    csv_writer = csv.writer(sys.stdout)
    csv_writer.writerows(csv_output)


def aws_managed_policies(args):
    sso_admin = boto3.client('sso-admin')
    sso_instance = list(boto3_paginate(sso_admin, 'list_instances'))[0]
    sso_instance_arn = sso_instance['InstanceArn']
    sso_instance_identity_store_id = sso_instance['IdentityStoreId']

    permission_sets = boto3_paginate(sso_admin, 'list_permission_sets', InstanceArn=sso_instance_arn)
    csv_output = [['ARN', 'Name', 'Description', 'Docs link']]

    aws_managed_policies = {}

    for permission_set_arn in permission_sets:
        permission_set = sso_admin.describe_permission_set(InstanceArn=sso_instance_arn, PermissionSetArn=permission_set_arn)['PermissionSet']
        permission_set_managed_policies = boto3_paginate(sso_admin, 'list_managed_policies_in_permission_set', InstanceArn=sso_instance_arn, PermissionSetArn=permission_set_arn)

        for managed_policy in permission_set_managed_policies:
            managed_policy_name = managed_policy['Name']
            managed_policy_arn = managed_policy['Arn']
            if managed_policy_arn.startswith('arn:aws:iam::aws:policy/'):
                aws_managed_policies[managed_policy_arn] = managed_policy_name

    iam = boto3.client('iam')
    for aws_managed_policy_arn, aws_managed_policy_name in aws_managed_policies.items():
        try:
            policy = iam.get_policy(PolicyArn=aws_managed_policy_arn)['Policy']
        except iam.exceptions.NoSuchEntityException:
            policy_description = '!not found'
            policy_docs_link = ''
            continue
        policy_description = policy['Description']
        policy_docs_link = f'https://docs.aws.amazon.com/aws-managed-policy/latest/reference/{aws_managed_policy_name}.html'
        if args.check_links:
            try:
                response = requests.get(policy_docs_link)
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                # Print the traceback to stderr
                print(e, file=sys.stderr)
                policy_docs_link = ''
        csv_output.append([aws_managed_policy_arn, aws_managed_policy_name, policy_description, policy_docs_link])

    # Use Python's csv module to print the CSV output
    csv_writer = csv.writer(sys.stdout)
    csv_writer.writerows(csv_output)

def get_users_with_enabled_status(identity_store_id):
    session = botocore.session.Session()
    region = session.get_config_variable('region')
    sigv4 = SigV4Auth(session.get_credentials(), 'identitystore', region)
    endpoint = f'https://up.sso.{region}.amazonaws.com/identitystore/'
    data = json.dumps( {"IdentityStoreId":identity_store_id, "MaxResults":100 })
    headers = {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSIdentityStoreService.SearchUsers'
    }
    request = AWSRequest(method='POST', url=endpoint, data=data, headers=headers)

    sigv4.add_auth(request)
    prepped = request.prepare()

    response = requests.post(prepped.url, headers=prepped.headers, data=data)
    return response.json()

def get_users_is_active_status(identity_store_id):
    is_active = {}
    for user in get_users_with_enabled_status(identity_store_id)['Users']:
        is_active[user['UserId']] = user['Active']
    return is_active

def users(args):
    sso_admin = boto3.client('sso-admin')
    sso_instance = list(boto3_paginate(sso_admin, 'list_instances'))[0]
    sso_instance_arn = sso_instance['InstanceArn']
    sso_instance_identity_store_id = sso_instance['IdentityStoreId']

    # Not supported by boto3, see https://github.com/boto/boto3/issues/3691
    users_is_active_status = get_users_is_active_status(sso_instance_identity_store_id)

    identitystore = boto3.client('identitystore')
    users = boto3_paginate(identitystore, 'list_users', IdentityStoreId=sso_instance_identity_store_id)
    csv_output = [['ID', 'Username', 'Email', 'Display name', 'Status']]

    for user in users:
        user_id = user['UserId']
        user_name = user['UserName']
        user_email = user['Emails'][0]['Value']
        user_display_name = user['DisplayName']
        user_status = 'Enabled' if users_is_active_status.get(user_id) else 'Disabled'

        csv_output.append([user_id, user_name, user_email, user_display_name, user_status])

    # Use Python's csv module to print the CSV output
    csv_writer = csv.writer(sys.stdout)
    csv_writer.writerows(csv_output)

def main():
    parser = argparse.ArgumentParser(description='Retrieve information about AWS SSO permissions')

    subcommands = parser.add_subparsers(dest='subcommand', required=True)
    account_assignments_parser = subcommands.add_parser('account-assignments', help='Retrieve information about AWS SSO account assignments')
    account_assignments_parser.set_defaults(func=account_assignments)

    user_group_assignments_parser = subcommands.add_parser('user-group-assignments', help='Retrieve the list of groups and which users are assigned to them')
    user_group_assignments_parser.set_defaults(func=user_group_assignments)

    permissions_sets_parser = subcommands.add_parser('permissions-sets', help='Retrieve information about AWS SSO permission sets')
    permissions_sets_parser.set_defaults(func=permissions_sets)

    aws_managed_policies_parser = subcommands.add_parser('aws-managed-policies', help='For each AWS managed policy used by a permissions set, retrieve the link to the AWS docs for that policy')
    aws_managed_policies_parser.add_argument('--check-links', action='store_true', help='Check that the links are valid')
    aws_managed_policies_parser.set_defaults(func=aws_managed_policies)

    users_parser = subcommands.add_parser('users', help='Retrieve information about AWS SSO users')
    users_parser.set_defaults(func=users)

    args = parser.parse_args()

    args.func(args)


if __name__ == '__main__':
    main()
