"""/api/result serves a valid ScanResult and publishes it in the OpenAPI schema the frontend types come from.

httpx is not installed, so the route function is called directly instead of through TestClient.
"""

from api.main import app, result


def test_result_serves_sample_when_no_report():
    r = result()
    assert len(r.assets) == 39 and len(r.sessions) == 7


def test_openapi_exposes_scan_result():
    schema = app.openapi()
    ref = schema["paths"]["/api/result"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert ref["$ref"].endswith("/ScanResult")
    assert {"ScanResult", "CryptoAsset", "Finding", "TLSSession", "RiskSummary"} <= set(
        schema["components"]["schemas"]
    )
