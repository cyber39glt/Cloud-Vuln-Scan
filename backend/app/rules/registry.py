"""The list of enabled rules.

An explicit list (rather than automatic discovery) makes it obvious what runs.
A test fails if a rule module exists but is missing here.
"""

from app.rules.aws.iam_account import AdministratorAccessOnUsers, WeakPasswordPolicy
from app.rules.aws.iam_root import RootAccountAccessKeys, RootAccountWithoutMfa
from app.rules.aws.iam_users import ConsoleUserWithoutMfa, UnusedAccessKeys
from app.rules.aws.log_001_cloudtrail_multi_region import CloudTrailMultiRegionLogging
from app.rules.aws.rds_public import RdsInstancePublic
from app.rules.aws.s3_public import S3AccountBlockPublicAccessOff, S3BucketPublic
from app.rules.azure.activity_log import ActivityLogNotExported
from app.rules.azure.defender import DefenderPlansDisabled
from app.rules.azure.sql_exposure import SqlServerAllowsAllAzureServices, SqlServerOpenToInternet
from app.rules.azure.sto_001_blob_public_access import StorageAccountAllowsPublicBlobAccess
from app.rules.azure.storage_transport import StorageAccountAllowsHttp, StorageAccountWeakTls
from app.rules.base import Rule
from app.rules.common.net_001_ssh_open_to_internet import SshOpenToInternet
from app.rules.common.net_002_rdp_open_to_internet import RdpOpenToInternet

ALL_RULES: tuple[Rule, ...] = (
    SshOpenToInternet(),
    RdpOpenToInternet(),
    # AWS
    RootAccountWithoutMfa(),
    RootAccountAccessKeys(),
    ConsoleUserWithoutMfa(),
    UnusedAccessKeys(),
    WeakPasswordPolicy(),
    AdministratorAccessOnUsers(),
    S3AccountBlockPublicAccessOff(),
    S3BucketPublic(),
    RdsInstancePublic(),
    CloudTrailMultiRegionLogging(),
    # Azure
    StorageAccountAllowsPublicBlobAccess(),
    StorageAccountAllowsHttp(),
    StorageAccountWeakTls(),
    SqlServerOpenToInternet(),
    SqlServerAllowsAllAzureServices(),
    ActivityLogNotExported(),
    DefenderPlansDisabled(),
)
