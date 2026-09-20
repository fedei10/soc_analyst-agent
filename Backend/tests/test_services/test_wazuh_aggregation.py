"""Full-population alert aggregation.

`search_alerts` is capped at a document limit, so counting its rows answers
"which IP dominates the sample I was handed", not "which IP dominates the 871
matching alerts". These checks pin that the aggregation selects the same
population as a matching search, reports its coverage as complete, and is
honest about how many documents actually carry the field it ranked on.
"""

import json

import pytest

from app.db.repositories.reports import InMemoryReportRepository
from app.services.wazuh.indexer_client import WazuhIndexerClient
from app.soc_assistant.tool_agent import build_tools


class RecordingOpenSearch:
    def __init__(self, response):
        self.response = response
        self.bodies = []

    def search(self, index, body, **_options):
        self.bodies.append((index, body))
        return self.response

    def close(self):
        pass


def aggregation_response(total=871):
    return {
        "hits": {"total": {"value": total}},
        "aggregations": {
            "by_source_ip": {
                "buckets": [
                    {"key": "192.0.2.10", "doc_count": 512},
                    {"key": "192.0.2.77", "doc_count": 128},
                ]
            },
            "source_ip_present": {"value": 640},
            "by_target_user": {"buckets": [{"key": "root", "doc_count": 400}]},
            "target_user_present": {"value": 400},
            "by_agent": {"buckets": [{"key": "linux-vm", "doc_count": 871}]},
            "by_level": {"buckets": [{"key": 10, "doc_count": 871}]},
            "by_rule": {
                "buckets": [
                    {
                        "key": "5712",
                        "doc_count": 640,
                        "sample": {
                            "hits": {
                                "hits": [
                                    {
                                        "_source": {
                                            "rule": {
                                                "description": (
                                                    "sshd: brute force trying "
                                                    "to get access"
                                                ),
                                                "level": 10,
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                    }
                ]
            },
        },
    }


def test_aggregation_counts_the_whole_population_not_a_page():
    client = RecordingOpenSearch(aggregation_response())

    result = WazuhIndexerClient(client=client).aggregate_alerts(
        hours=24, min_level=10
    )

    _, body = client.bodies[0]
    # size=0 is what makes this a population count rather than a page of docs.
    assert body["size"] == 0
    assert body["track_total_hits"] is True
    assert result["total_alerts"] == 871
    assert result["by_source_ip"]["192.0.2.10"] == 512
    assert result["coverage"] == {
        "matched": 871,
        "returned": 871,
        "truncated": False,
        "status": "complete",
        "aggregation_scope": "full_population",
        "note": (
            "Counts were computed by the indexer over every matching "
            "document, not over a returned sample."
        ),
    }


def test_aggregation_reports_how_many_alerts_carry_the_ranked_field():
    client = RecordingOpenSearch(aggregation_response())

    result = WazuhIndexerClient(client=client).aggregate_alerts(hours=24)

    # 640 of 871 carry a source IP: the ranking covers a subset, and the
    # analyst has to be able to see that rather than infer it.
    assert result["alerts_with_source_ip"] == 640
    assert result["total_alerts"] == 871
    assert result["source_ip_field"] == "data.srcip"


def test_top_rules_carry_their_description_so_no_second_lookup_is_needed():
    client = RecordingOpenSearch(aggregation_response())

    result = WazuhIndexerClient(client=client).aggregate_alerts(hours=24)

    assert result["by_rule"] == [
        {
            "rule_id": "5712",
            "count": 640,
            "description": "sshd: brute force trying to get access",
            "level": 10,
        }
    ]


def test_aggregation_selects_the_same_population_as_a_matching_search():
    search_client = RecordingOpenSearch(
        {"hits": {"total": {"value": 0}, "hits": []}}
    )
    agg_client = RecordingOpenSearch(aggregation_response())
    filters = {
        "hours": 6,
        "min_level": 10,
        "agent_id": "001",
        "source_ip": "192.0.2.10",
        "authentication_only": True,
    }

    WazuhIndexerClient(client=search_client).search_alerts(limit=10, **filters)
    WazuhIndexerClient(client=agg_client).aggregate_alerts(**filters)

    # Same filter clause, or the aggregation's total would not describe the
    # rows the search returns.
    assert (
        search_client.bodies[0][1]["query"] == agg_client.bodies[0][1]["query"]
    )


@pytest.mark.parametrize("top", [0, 51])
def test_top_is_bounded(top):
    client = RecordingOpenSearch(aggregation_response())

    with pytest.raises(ValueError):
        WazuhIndexerClient(client=client).aggregate_alerts(top=top)


def test_the_analyst_tool_exposes_the_aggregation_read_only():
    class Gateway:
        def __init__(self):
            self.calls = []

        def aggregate_alerts(self, **kwargs):
            self.calls.append(kwargs)
            return {"total_alerts": 871, "coverage": {"matched": 871}}

    gateway = Gateway()
    tools = {
        item.name: item
        for item in build_tools(
            gateway,
            report_repository=InMemoryReportRepository(),
            investigations=None,
            organization_id="org-a",
            created_by="analyst-1",
            conversation_id="conv-1",
        )
    }

    raw = tools["aggregate_alerts"].invoke(
        {"hours": 24, "min_level": 10, "top": 99}
    )

    assert json.loads(raw)["total_alerts"] == 871
    # Model-supplied arguments are clamped before they reach the indexer.
    assert gateway.calls[0]["top"] == 50
    assert gateway.calls[0]["min_level"] == 10
