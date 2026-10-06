"""The list of enabled rules.

An explicit list (rather than automatic discovery) makes it obvious what runs.
A test fails if a rule module exists but is missing here.
"""

from app.rules.aws.log_001_cloudtrail_multi_region import CloudTrailMultiRegionLogging
from app.rules.azure.sto_001_blob_public_access import StorageAccountAllowsPublicBlobAccess
from app.rules.base import Rule
from app.rules.common.net_001_management_ports_open import ManagementPortsOpenToInternet

ALL_RULES: tuple[Rule, ...] = (
    ManagementPortsOpenToInternet(),
    CloudTrailMultiRegionLogging(),
    StorageAccountAllowsPublicBlobAccess(),
)
