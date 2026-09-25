from netwatch.alerts import (
    create_port_scan_alerts, 
    create_host_sweep_alerts,
    create_high_volume_flow_alerts,
    create_excessive_syn_alerts,
    get_count_severity,
    get_volume_severity,
    generate_alerts,
    )



def test_create_port_scan_alerts():
    results = [
        ("10.0.0.10", "10.0.0.20", 25)
    ]

    alerts = create_port_scan_alerts(results)

    assert len(alerts) == 1
    alert = alerts[0]


    assert alert["type"] == "port_scan"
    assert alert["severity"] == "medium"
    assert alert["source_ip"] == "10.0.0.10"
    assert alert["destination_ip"] == "10.0.0.20"
    assert alert["evidence"]["unique_ports"] == 25
    assert "25" in alert["explanation"]



def test_create_host_sweep_alerts():
    results = [
        ("10.0.0.60", 25)
    ]

    alerts = create_host_sweep_alerts(results)

    assert len(alerts) == 1
    alert = alerts[0]


    assert alert["type"] == "host_sweep"
    assert alert["severity"] == "medium"
    assert alert["source_ip"] == "10.0.0.60"
    assert alert["evidence"]["unique_hosts"] == 25
    assert "25" in alert["explanation"]


def test_create_high_volume_flow_alerts():
    results = [
        ("10.0.0.70", "10.0.0.80", 51000, 443, "TCP", 2_000_000)
    ]

    alerts = create_high_volume_flow_alerts(results)

    assert len(alerts) == 1 
    alert = alerts[0]


    assert alert["type"] == "high_volume_flow"
    assert alert["severity"] == "medium"
    assert alert["source_ip"] == "10.0.0.70"
    assert alert["destination_ip"] == "10.0.0.80"
    assert alert["evidence"]["source_port"] == 51000
    assert alert["evidence"]["destination_port"] == 443
    assert alert["evidence"]["protocol"] == "TCP"
    assert alert["evidence"]["total_bytes"] == 2_000_000
    assert "2000000" in alert["explanation"]


def test_create_excessive_syn_alerts():
    results = [
        ("10.0.0.90", "10.0.0.100", 75)
    ]

    alerts = create_excessive_syn_alerts(results)

    assert len(alerts) == 1
    alert = alerts[0]

    assert alert["type"] == "excessive_syn"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "10.0.0.90"
    assert alert["destination_ip"] == "10.0.0.100"
    assert alert["evidence"]["syn_count"] == 75
    assert "75" in alert["explanation"]


def test_count_severity_boundaries():
    assert get_count_severity(19) == "low"
    assert get_count_severity(20) == "medium"
    assert get_count_severity(49) == "medium"
    assert get_count_severity(50) == "high"


def test_volume_severity_boundaries():
    assert get_volume_severity(999_999) == "low"
    assert get_volume_severity(1_000_000) == "medium"
    assert get_volume_severity(9_999_999) == "medium"
    assert get_volume_severity(10_000_000) == "high"


def test_generate_alerts():
    port_scan_results = [
        ("10.0.0.10", "10.0.0.20", 25)
    ]

    host_sweep_results = [
        ("10.0.0.60", 25)
    ]

    high_volume_results = [
        ("10.0.0.70", "10.0.0.80", 51000, 443, "TCP", 2_000_000)
    ]

    excessive_syn_results = [
        ("10.0.0.90", "10.0.0.100", 75)
    ]

    alerts = generate_alerts(
        port_scan_results,
        host_sweep_results,
        high_volume_results,
        excessive_syn_results,
    )

    assert len(alerts) == 4

    assert alerts[0]["type"] == "port_scan"
    assert alerts[1]["type"] == "host_sweep"
    assert alerts[2]["type"] == "high_volume_flow"
    assert alerts[3]["type"] == "excessive_syn"



