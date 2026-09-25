def create_port_scan_alerts(results):
    alerts = []

    for result in results:
        source_ip, destination_ip, unique_ports = result
        severity = get_count_severity(unique_ports)
        alert = {
            "type": "port_scan",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "evidence": {
                "unique_ports": unique_ports
            },
            "severity": severity,
            "explanation": f"Source {source_ip} sent TCP SYN packets to {unique_ports} unique ports on destination {destination_ip}",
            

        }

        alerts.append(alert)

    return alerts


def get_count_severity(count):
    if count < 20:
        severity = "low"
    elif  count < 50:
        severity = "medium"
    else:
        severity = "high"

    return severity


def create_host_sweep_alerts(results):
    alerts = []
    for result in results:
        source_ip, unique_hosts = result
        severity = get_count_severity(unique_hosts)
        alert = {
                 "type": "host_sweep",
                 "source_ip": source_ip,
                 "evidence": {
                     "unique_hosts": unique_hosts
                    },
                "severity": severity,
                "explanation": f"Source {source_ip} sent TCP SYN packets to {unique_hosts} unique hosts",
                    
        
                }
        
        alerts.append(alert)
        
    return alerts


def create_high_volume_flow_alerts(results):
    alerts = []
    for result in results:
        source_ip, destination_ip, source_port, destination_port, protocol, total_bytes = result
        severity = get_volume_severity(total_bytes)
        alert = {
             "type": "high_volume_flow",
             "source_ip": source_ip,
             "destination_ip": destination_ip,
             "evidence": {
                  "source_port": source_port,
                  "destination_port": destination_port,
                  "protocol": protocol,
                  "total_bytes": total_bytes,
             },
             "severity": severity,
             "explanation": f"{protocol} flow from {source_ip}:{source_port} to {destination_ip}:{destination_port} transferred {total_bytes} bytes",

            }
            
        alerts.append(alert)
            
    return alerts

def get_volume_severity(total_bytes):
    if total_bytes < 1_000_000:
        severity = "low"
    elif total_bytes < 10_000_000:
        severity = "medium"
    else:
        severity = "high"

    return severity
  
def create_excessive_syn_alerts(results):
    alerts = []
    for result in results:
        source_ip, destination_ip, syn_count = result
        severity = get_count_severity(syn_count)
        alert = {
            "type": "excessive_syn",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "evidence":{
                "syn_count": syn_count,
            },
            "severity": severity,
            "explanation": f"Source {source_ip} sent {syn_count} TCP SYN packets to destination {destination_ip}"
      
        }
        alerts.append(alert)
    return alerts 


def generate_alerts(
    port_scan_results,
    host_sweep_results,
    high_volume_results,
    excessive_syn_results,
):
    alerts = []

    alerts.extend(create_port_scan_alerts(port_scan_results))
    alerts.extend(create_host_sweep_alerts(host_sweep_results))
    alerts.extend(create_high_volume_flow_alerts(high_volume_results))
    alerts.extend(create_excessive_syn_alerts(excessive_syn_results))
    return alerts