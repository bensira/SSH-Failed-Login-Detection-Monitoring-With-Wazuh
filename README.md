# SSH Failed Login Detection and Monitoring with Wazuh

## Project Overview

This project demonstrates how to detect, monitor, and investigate failed SSH authentication attempts using Wazuh SIEM.

The objective was to simulate unsuccessful SSH login attempts, analyze security events, create SIEM visualizations, and configure an alert for repeated failed authentication attempts.

## Tools Used

- Wazuh SIEM
- Kali Linux
- SSH
- Wazuh Dashboard
- OpenSearch Alerting

## 1. Lab Environment

Testing was performed locally on Kali Linux using SSH.

A non-existent username was used to simulate failed authentication:

```bash
ssh invaliduser987@127.0.0.1
```

The terminal returned:

```text
Permission denied (publickey,password).
```

## 2. Detection and Analysis

Wazuh Rule **5710** was used to identify SSH login attempts involving a non-existent username.

Key event details:

| Field | Value |
|---|---|
| Rule ID | 5710 |
| Host | Kali Linux |
| Source IP | 127.0.0.1 |
| Username | invaliduser987 |
| Event | Failed SSH authentication |

To inspect the number of matching events in the local alert log:

```bash
sudo grep -c '"id":"5710"' /var/ossec/logs/alerts/alerts.json
```

The command returned 57 matching events at the time of verification.

## 3. SIEM Dashboard

Created a dashboard named **SOC Security Monitoring Dashboard** with two visualizations.

### Visualization 1: SSH Failed Login Attempts Over Time

- Chart type: Line graph
- Metric: Count
- X-axis: Timestamp
- Filter: `rule.id = 5710`

This visualization displays failed SSH authentication activity over time.

### Visualization 2: Failed SSH Logins by Source IP

- Chart type: Pie chart
- Metric: Count
- Field: `data.srcip.keyword`
- Filter: `rule.id = 5710`

This visualization displays the distribution of failed SSH login attempts by source IP address.

## 4. Alert Configuration

Created a monitor named **Repeated SSH Failed Logins**.

Configuration:

- Monitor type: Per query monitor
- Execution frequency: Every 1 minute
- Detection rule: Wazuh Rule 5710
- Detection window: 10 minutes

### Extraction Query

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "term": {
            "rule.id": 5710
          }
        },
        {
          "range": {
            "timestamp": {
              "gte": "now-10m",
              "lte": "now"
            }
          }
        }
      ]
    }
  }
}
```

### Trigger Condition

Trigger name: **More Than 5 Failed SSH Logins**

```javascript
ctx.results[0].hits.total.value > 5
```

Severity: 2

The intended condition was to generate an alert when more than five matching failed SSH login events occurred within ten minutes.

## 5. Testing

Generated six failed SSH login attempts using:

```bash
for i in {1..6}; do ssh -o BatchMode=yes invaliduser987@127.0.0.1; done
```

The attempts returned authentication failure messages.

The monitor showed:

- Status: Active
- Errors: 0

An alert record was observed in the Alerts section with:

- State: Completed
- Severity: 2
- Alert start time: Recorded

## 6. Key Learning Outcomes

Through this project, I gained practical experience in:

- SSH authentication monitoring.
- Wazuh detection rules.
- Security event investigation.
- SIEM dashboard creation.
- OpenSearch query configuration.
- Threshold-based alerting.
- Basic security monitoring and analysis.

## 7. Conclusion

This project strengthened my foundational understanding of SIEM operations and security monitoring.

It demonstrated how Wazuh can be used to detect authentication failures, visualize suspicious activity, and configure alerts to support security monitoring within a Security Operations Centre (SOC).

**Project Category:** Blue Team | SOC Monitoring | SIEM | Threat Detection
