import logging
import logging.config
import os
import time
import uuid
from collections import OrderedDict
from typing import Any, Dict, List

from azure.core.exceptions import ResourceExistsError
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
# We use the v2015_07_01 version of the RoleAssignmentCreateParameters and RoleAssignmentProperties to avoid
#   the need to specify the principal_type parameter.
from azure.mgmt.authorization.v2015_07_01.models import RoleAssignmentCreateParameters, RoleAssignmentProperties
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.keyvault.models import Vault

from core.utils import load_config, setup_logging, setup_basic_argparser

# Permissions mapping for different roles in Azure Key Vault
PERMISSIONS_MAPPING: Dict[str, OrderedDict[str, List[str]]] = {
    "secrets": OrderedDict({
        "Key Vault Secrets Officer": ['Set', 'Delete', 'Recover', 'Backup', 'Restore', 'Purge'],
        "Key Vault Secrets User": ['Get', 'List']
    }),
    "certificates": OrderedDict({
        "Key Vault Certificates Officer": ['Update', 'Create', 'Import', 'Delete', 'Recover', 'Backup',
                                           'Restore', 'ManageContacts', 'ManageIssuers', 'GetIssuers',
                                           'ListIssuers', 'SetIssuers', 'DeleteIssuers', 'Purge'],
        "Key Vault Certificate User": ['Get', 'List']
    }),
    "keys": OrderedDict({
        "Key Vault Crypto Officer": ['Create', 'Import', 'Delete', 'Recover', 'Restore',
                                     'GetRotationPolicy', 'SetRotationPolicy', 'Rotate', 'Purge', 'Release'],
        "Key Vault Crypto User": ['List', 'Update', 'Backup', 'Encrypt', 'Decrypt', 'Verify', 'Sign'],
        "Key Vault Crypto Service Encryption User": ['Get', 'UnwrapKey', 'WrapKey'],
        "Key Vault Crypto Service Release User": ['Release']
    }),
    "admin": OrderedDict({
        "Key Vault Administrator": ['Key Vault Secrets Officer', 'Key Vault Certificates Officer',
                                    'Key Vault Crypto Officer']
    })
}


def role_matches(policy_permissions: List[str], role_permissions: List[str]) -> bool:
    """Check if any role permission matches the policy permissions."""
    policy_permissions = [permission.lower() for permission in policy_permissions]
    return any(permission.lower() in policy_permissions for permission in role_permissions)


def load_azure_role_definitions(auth_client: AuthorizationManagementClient, vault: Vault) -> Dict[str, str]:
    """Load role definitions for the given vault."""
    return {role.role_name: role.id for role in auth_client.role_definitions.list(vault.id)}


def assign_roles(vault: Vault, auth_client: AuthorizationManagementClient) -> None:
    """Assign roles to users based on their policy permissions."""
    role_definitions = load_azure_role_definitions(auth_client, vault)
    for policy in vault.properties.access_policies:
        role_definition_names = find_role_name_from_access_policies(policy)
        push_role_assignment(auth_client, vault, policy, role_definition_names, role_definitions)


def find_role_name_from_access_policies(policy: Any) -> List[str]:
    """Determine which roles match the given policy permissions."""
    role_names = []
    for category, roles in PERMISSIONS_MAPPING.items():
        for role_name, permissions in roles.items():
            if role_matches(getattr(policy.permissions, category, []), permissions):
                role_names.append(role_name)
                break

    if role_names == PERMISSIONS_MAPPING['admin']['Key Vault Administrator']:
        role_names = ['Key Vault Administrator']

    return role_names


def push_role_assignment(auth_client: AuthorizationManagementClient, vault: Vault, policy: Any,
                         role_names: List[str], role_definitions: Dict[str, str]) -> None:
    """Log the role assignments and handle the actual assignment via Azure's API."""

    logger = logging.getLogger(__name__)

    for role_name in role_names:
        role_id = role_definitions.get(role_name)
        if role_id:
            try:
                auth_client.role_assignments.create(
                    vault.id, str(uuid.uuid4()), RoleAssignmentCreateParameters(
                        properties=RoleAssignmentProperties(role_definition_id=role_id, principal_id=policy.object_id)
                    )
                )
                logger.info(f"Assigned {role_name} (ID: {role_id}) to {policy.object_id}")
            except ResourceExistsError:
                logger.warning(f"RBAC assignment already exists for {role_name} (ID: {role_id}) to {policy.object_id}")


def main(subscription_id: str, vault_name: str, resource_group_name: str) -> None:
    """Main function to orchestrate the role assignment process."""

    logger = logging.getLogger(__name__)

    start_time = time.time()

    credential = DefaultAzureCredential()
    kv_client = KeyVaultManagementClient(credential, subscription_id)
    auth_client = AuthorizationManagementClient(credential, subscription_id)

    vault = kv_client.vaults.get(resource_group_name, vault_name)
    assign_roles(vault, auth_client)

    logger.info(f"Execution time: {time.time() - start_time:.2f} seconds")


if __name__ == "__main__":
    parser = setup_basic_argparser()
    args = parser.parse_args()

    setup_logging(os.path.join(str(args.logging_config_file)))
    _logger = logging.getLogger(__name__)

    config = load_config(os.path.join(str(args.config_file)))

    main(
        subscription_id=config['subscription_id'],
        vault_name=config['vault_name'],
        resource_group_name=config['resource_group_name']
    )
