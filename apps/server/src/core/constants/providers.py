"""Known provider keys for provider-agnostic onboarding."""

from enum import Enum


class Provider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    ORACLE = "ORACLE"
    ALIBABA = "ALIBABA"
    DIGITALOCEAN = "DIGITALOCEAN"
    HETZNER = "HETZNER"
    OVH = "OVH"
    IBM = "IBM"
    VMWARE = "VMWARE"
    ON_PREM = "ON_PREM"
    OTHER = "OTHER"


PROVIDERS: list[str] = [p.value for p in Provider]
