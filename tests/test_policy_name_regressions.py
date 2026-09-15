"""HTML entities in UAP names must not become absent templates or unrecoverable create conflicts."""
from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from sia.clients import UAPClient
from sia.http import HttpClient, SIAApiError
from tests.fakes import FakeResponse, FakeSession
from tests.test_resolve_reconcile import DEFAULTS, ONE, TEMPLATE, VAULT, WEB01, inputs, make


def client_with(responses):
    session = FakeSession(responses)
    http = HttpClient(lambda force=False: "tok", session=session, max_retries=0, sleep=lambda _: None)
    return UAPClient(http, "https://u"), session


def policy(name, policy_id="p1"):
    return {"metadata": {"name": name, "policyId": policy_id}}


@pytest.mark.parametrize(("requested", "returned"), [
    ("R&D policy", "R&amp;D policy"),
    ("R&amp;D policy", "R&D policy"),
    ("R&D policy", "r&#38;d POLICY"),
    ('<ops> "Admin"', "&lt;OPS&gt; &quot;ADMIN&quot;"),
    ("Ops' access", "Ops&#x27; access"),
    ("Plain Policy", "pLAIN policy"),
])
@pytest.mark.parametrize("search_miss", [False, True])
def test_exact_policy_lookup_decodes_both_names_before_casefold(requested, returned, search_miss):
    found = policy(returned)
    responses = [FakeResponse(200, {"results": []})] if search_miss else []
    responses.append(FakeResponse(200, {"results": [found, policy(returned + " extra", "p2")]}))
    client, session = client_with(responses)

    assert client.find_policy_by_name(requested) == found
    assert len(session.requests) == (2 if search_miss else 1)
    assert client.search_reliable is not search_miss
    assert found["metadata"]["name"] == returned  # Matching must not rewrite the tenant response.


@pytest.mark.parametrize("search_miss", [False, True])
def test_decoded_policy_name_collisions_still_reject_distinct_ids(search_miss):
    responses = [FakeResponse(200, {"results": []})] if search_miss else []
    responses.append(FakeResponse(200, {"results": [policy("R&D policy"), policy("r&amp;d POLICY", "p2")]}))
    client, _ = client_with(responses)

    with pytest.raises(SIAApiError, match="ambiguous across object ids: p1, p2") as error:
        client.find_policy_by_name("R&D policy")
    assert error.value.cause == "ambiguous_response"


def test_decoded_policy_name_observations_with_the_same_id_are_deduplicated():
    first = policy("R&amp;D policy")
    client, _ = client_with([FakeResponse(200, {"results": [first, policy("R&D policy")]})])

    assert client.find_policy_by_name("R&D policy") == first


def test_reconciler_loads_an_html_escaped_template_through_real_uap_client():
    seed, sia, original, _ = make(ONE)
    assert seed.run().failures == 0
    template = copy.deepcopy(TEMPLATE)
    template["metadata"]["name"] = "R&amp;D reference"
    client, session = client_with([
        FakeResponse(200, {"results": [policy("R&amp;D reference", "tpl")]}),
        FakeResponse(200, template),
        FakeResponse(200, {"results": copy.deepcopy(original.policies)}),
    ])
    rec = make(ONE, sia=sia, uap=client, dry_run=True, only="policies",
               defaults=replace(DEFAULTS, template_policy="R&D reference"))[0]

    result = rec.run()

    assert result.failures == 0
    assert rec._template["conditions"] == TEMPLATE["conditions"]
    assert session.requests[1][:2] == ("GET", "https://u/api/policies/tpl")
    assert all(method == "GET" for method, _, _ in session.requests)
    assert not session.responses


@pytest.mark.parametrize("search_miss", [False, True])
def test_reconciler_recovers_409_for_an_html_escaped_name_through_real_uap_client(search_miss):
    inp = inputs([replace(WEB01, policy_name="R&D policy")], [VAULT])
    seed, sia, original, _ = make(inp)
    assert seed.run().failures == 0
    existing = copy.deepcopy(original.policies[0])
    existing["metadata"]["name"] = "R&amp;D policy"
    existing["metadata"]["policyTags"] = ["manual"]
    responses = [
        FakeResponse(200, {"results": []}),  # The owner-tag snapshot excludes this unmanaged policy.
        FakeResponse(409, {"message": "policy name already exists"}),
    ]
    if search_miss:
        responses.append(FakeResponse(200, {"results": []}))
    responses.append(FakeResponse(200, {"results": [existing]}))
    client, session = client_with(responses)

    result = make(inp, sia=sia, uap=client, only="policies")[0].run()

    outcome = result.servers[0].policy
    assert result.failures == 0 and outcome.status == "exists"
    assert outcome.ref == existing["metadata"]["policyId"] and "unmanaged" in outcome.detail
    assert [method for method, _, _ in session.requests].count("POST") == 1
    assert not any(method == "PUT" for method, _, _ in session.requests)
    assert not session.responses
