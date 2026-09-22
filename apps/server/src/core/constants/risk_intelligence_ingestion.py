"""Constants for the Risk Intelligence ingestion foundation."""

DEFAULT_COLLECTOR_PROFILE = "subfinder_amass_nmap_nuclei"

#: The `AssetFinding.domain` scanner-sourced findings are written under.
#:
#: One definition, because the table is shared. The asset-monitoring engine
#: writes its own rows into `asset_findings` under the `network` domain — 160 of
#: them in organisation 7, none from a scanner — so any reader that counts the
#: table rather than filtering on this reports a scan result on artefacts no
#: scan has ever reached.
FINDING_DOMAIN_RISK_INTELLIGENCE = "risk_intelligence_ingestion"
INGESTION_BATCH_CREATED_EVENT = "risk_intelligence_ingestion_batch_created"
INGESTION_BATCH_FETCHED_EVENT = "risk_intelligence_ingestion_batch_fetched"
INGESTION_BATCH_NORMALIZED_EVENT = "risk_intelligence_ingestion_batch_normalized"
INGESTION_BATCH_ANALYZED_EVENT = "risk_intelligence_ingestion_batch_analyzed"
INGESTION_BATCH_REVIEWED_EVENT = "risk_intelligence_ingestion_batch_reviewed"

__all__ = [
    "DEFAULT_COLLECTOR_PROFILE",
    "FINDING_DOMAIN_RISK_INTELLIGENCE",
    "INGESTION_BATCH_CREATED_EVENT",
    "INGESTION_BATCH_FETCHED_EVENT",
    "INGESTION_BATCH_NORMALIZED_EVENT",
    "INGESTION_BATCH_ANALYZED_EVENT",
    "INGESTION_BATCH_REVIEWED_EVENT",
]
