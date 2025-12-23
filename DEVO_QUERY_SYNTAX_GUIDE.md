# DEVO Query Syntax Alignment Guide

## Overview

This document provides guidance on aligning the conceptual queries in this library with actual DEVO LINQ syntax standards used in production DEVO environments.

## Critical Syntax Differences

### 1. Multiple SELECT Statements

**Our Template Syntax:**
```sql
from firewall.traffic
where action = "allow"
select
  eventdate,
  srcip,
  dstip,
  action
```

**Actual DEVO LINQ Syntax:**
```sql
from firewall.traffic
select eventdate
select srcip as source_ip
select dstip as destination_ip
select action
where action = "allow"
```

**Key Difference**: DEVO uses multiple `select` statements (one per field or group of fields), not a single select block with comma-separated fields.

### 2. Field Naming Conventions

**Common Field Name Variations:**

| Our Templates | Actual DEVO | Context |
|---------------|-------------|---------|
| `srcip` | `srcaddr` | Source IP address |
| `dstip` | `dstaddr` | Destination IP address |
| `srcport` | `srcport` | Usually consistent |
| `dstport` | `dstport` | Usually consistent |
| `eventdate` | `eventdate` | Usually consistent |
| `domain` | Varies by source | Check your data source |
| `filename` | Varies by source | Check your data source |

**Note**: Field names vary by data source and table schema. Always verify against your specific DEVO tables.

### 3. DEVO-Specific Functions

Our templates use generic SQL functions. DEVO has specialized functions:

#### String Matching Functions

**`weakhas(field, "value")`** - Weak/fuzzy string matching
```sql
-- Instead of: where action = "ACCEPT"
where weakhas(action, "ACCEPT")  -- More flexible matching
```

#### Geographic Functions

**`mm2country(ip_field)`** - Map IP to country
```sql
select mm2country(dstaddr) as dst_country
```

**`mm2city(ip_field)`** - Map IP to city
```sql
select mm2city(srcaddr) as src_city
```

**`mm2coordinates(ip_field)`** - Get lat/long coordinates
```sql
select mm2coordinates(srcaddr) as src_coords
```

#### IP Classification Functions

**`purpose(ip_field)`** - Classify IP purpose (public, private, etc.)
```sql
select purpose(srcaddr) as src_purpose
```

**`isPrivate(ip_field)`** - Check if IP is private
```sql
where not isPrivate(dstaddr)  -- Only public IPs
```

#### List Membership with Backticks

**`` `in`(list, value) ``** - Check if value is in list (note backticks)
```sql
-- Instead of: where country in ("US", "CA", "MX")
where `in`("US", "CA", "MX", mm2country(dstaddr))
```

**Note**: Some DEVO functions require backticks: `` `in`() ``, `` `not`() ``, etc.

#### Time/Date Functions

**`timestamp(field)`** - Convert to timestamp
**`timeslot(timespan, field)`** - Group by time slot
**`timedelta(value, unit)`** - Time difference calculations

#### Statistical Functions

**`stdev(field)`** - Standard deviation
**`percentile(field, percentage)`** - Calculate percentiles
**`mavg(field, window)`** - Moving average

### 4. WHERE Clause Placement

**Our Templates**: WHERE typically appears before SELECT
**DEVO**: WHERE can appear after SELECT statements

**Example:**
```sql
from firewall.traffic
select eventdate
select srcaddr
select dstaddr
select action
where weakhas(action, "ACCEPT")
and `in`("Balkans", "Belarus", "Russia", mm2country(dstaddr))
```

### 5. Aggregation and Grouping

**Our Template Syntax:**
```sql
select
  srcip,
  count() as event_count
group by srcip
having event_count > 100
```

**DEVO LINQ Syntax:**
```sql
select srcaddr
select count() as event_count
group by srcaddr
having event_count > 100
```

### 6. Window Functions

**lag() and lead() functions:**
```sql
-- Our template
lag(geolocation.latitude) over username as prev_lat

-- DEVO (likely similar, but verify)
select lag(geolocation.latitude) over username as prev_lat
```

## Data Source Table Naming

**Our Templates Use:**
- `firewall.traffic`
- `cloud.aws.cloudtrail`
- `siem.logins`
- `network.dns`

**Your Environment May Use:**
- `firewall.paloalto.traffic`
- `cloud.aws.vpc.flow`
- `azure.auditlogs`
- Vendor-specific table names

**Action Required**: Verify table names in your DEVO environment using the Data Search interface.

## Query Validation Checklist

Before deploying any query from this library:

- [ ] **Verify table names** exist in your DEVO environment
- [ ] **Check field names** using `from table.name select *` to see schema
- [ ] **Replace `srcip`/`dstip`** with `srcaddr`/`dstaddr` if needed
- [ ] **Convert single SELECT** to multiple SELECT statements
- [ ] **Add DEVO-specific functions** where appropriate:
  - [ ] Use `weakhas()` for flexible string matching
  - [ ] Use `mm2country()` for geo-enrichment
  - [ ] Use `purpose()` for IP classification
  - [ ] Use backtick functions `` `in`() `` for list membership
- [ ] **Test query** in DEVO Query Interface with small time window first
- [ ] **Verify performance** on larger datasets
- [ ] **Tune thresholds** based on your environment baseline

## Example: Template vs. Production Query

### Template Query (From This Library)

```sql
from firewall.traffic
where threat_type = "wildfire"
  and verdict in ("malicious", "phishing")
  and action in ("alert", "block-url", "block-ip")
select
  eventdate,
  srcip,
  dstip,
  srcuser,
  dstport,
  application,
  filename,
  filetype,
  verdict,
  threat_id,
  threat_name,
  action,
  url
group by srcip, dstip, threat_name, filename
```

### Production DEVO Query (Aligned)

```sql
from firewall.paloalto.traffic
select eventdate
select srcaddr as srcip
select dstaddr as dstip
select srcuser
select dstport
select application
select filename
select filetype
select verdict
select threat_id
select threat_name
select action
select url
select mm2country(srcaddr) as src_country
select purpose(srcaddr) as src_purpose
where weakhas(threat_type, "wildfire")
  and `in`("malicious", "phishing", verdict)
  and `in`("alert", "block-url", "block-ip", action)
group by srcaddr, dstaddr, threat_name, filename
```

## Common Query Patterns

### Pattern 1: Basic Filtering with Geo-Enrichment

```sql
from firewall.traffic
select eventdate
select srcaddr
select dstaddr
select mm2country(dstaddr) as dst_country
select mm2city(dstaddr) as dst_city
select purpose(dstaddr) as dst_purpose
where weakhas(action, "ACCEPT")
  and not isPrivate(dstaddr)
```

### Pattern 2: Threat Intelligence Correlation

```sql
from firewall.traffic
select eventdate
select srcaddr
select dstaddr
select action
where `in`(select malicious_ip from threat.intel.ips, dstaddr)
  and weakhas(action, "ACCEPT")
```

### Pattern 3: Geographic Filtering

```sql
from cloud.aws.vpc.flow
select eventdate
select srcaddr
select dstaddr
select mm2country(dstaddr) as dst_country
where `in`("RU", "CN", "KP", "IR", mm2country(dstaddr))
  and weakhas(action, "ACCEPT")
```

### Pattern 4: Aggregation with Statistics

```sql
from siem.logins
select username
select count() as login_count
select countdistinct(srcaddr) as unique_ips
select stdev(login_duration) as duration_variance
group by username
every 1h
having login_count > 100
```

## DEVO Function Reference

### String Functions
- `weakhas(field, "string")` - Fuzzy string matching
- `contains(field, "substring")` - Substring check
- `length(field)` - String length
- `split(field, "delimiter")` - Split string

### Geo Functions
- `mm2country(ip)` - IP to country code
- `mm2city(ip)` - IP to city name
- `mm2coordinates(ip)` - IP to lat/long
- `mm2asn(ip)` - IP to ASN

### IP Functions
- `purpose(ip)` - IP classification
- `isPrivate(ip)` - Private IP check
- `isIPv4(field)` - IPv4 validation
- `isIPv6(field)` - IPv6 validation

### List Functions (with backticks)
- `` `in`(list, value) `` - Value in list
- `` `not`(condition) `` - Negation

### Time Functions
- `timestamp(field)` - Convert to timestamp
- `now()` - Current time
- `timeslot(span, field)` - Time grouping
- `timedelta(value, unit)` - Time arithmetic

### Statistical Functions
- `count()` - Count records
- `sum(field)` - Sum values
- `avg(field)` - Average
- `stdev(field)` - Standard deviation
- `percentile(field, pct)` - Percentile calculation
- `min(field)` / `max(field)` - Min/max

### Collection Functions
- `countdistinct(field)` - Count unique values
- `collectdistinct(field)` - Collect unique values
- `first(field)` / `last(field)` - First/last value

## Troubleshooting

### Common Errors

**Error: "Field not found: srcip"**
- **Solution**: Change `srcip` to `srcaddr` (or verify actual field name)

**Error: "Table not found: firewall.traffic"**
- **Solution**: Verify table name in your environment (may be `firewall.paloalto.traffic`)

**Error: "Syntax error near SELECT"**
- **Solution**: Split single SELECT into multiple SELECT statements

**Error: "Function 'in' not found"**
- **Solution**: Use backticks: `` `in`() ``

**Error: "Unknown function: mm2country"**
- **Solution**: Verify DEVO platform version supports geo functions

## Best Practices

1. **Always test queries in non-production** before creating alerts
2. **Start with small time windows** (5-10 minutes) when testing
3. **Use DEVO-specific functions** for better performance:
   - `weakhas()` instead of multiple OR conditions
   - `mm2country()` instead of joining geo tables
   - `` `in`() `` instead of multiple OR clauses
4. **Verify field names** by running `from table.name select *` first
5. **Add geo-enrichment** where useful for security context
6. **Use `purpose()` function** to classify IPs (public, private, etc.)
7. **Leverage DEVO's built-in functions** for efficiency
8. **Document any environment-specific customizations**

## Platform Version Differences

Different DEVO platform versions may have:
- Different function names
- Different table schemas
- Different syntax requirements
- Different available functions

**Always consult**: https://docs.devo.com/ for your specific platform version

## Migration Path

To migrate a template query to production:

1. **Identify the data source table** in your DEVO environment
2. **Run schema check**: `from table.name select *`
3. **Map template fields to actual fields**
4. **Convert to multiple SELECT statements**
5. **Add DEVO-specific functions** (geo, purpose, weakhas)
6. **Replace standard functions** with backtick versions if needed
7. **Test with small time window** (last 5 minutes)
8. **Validate results** match expected behavior
9. **Tune thresholds** based on your baseline
10. **Deploy to production** with appropriate alerting

## Additional Resources

- **DEVO Documentation**: https://docs.devo.com/
- **DEVO Query Language Reference**: https://docs.devo.com/confluence/ndt/latest/searching-data/queries
- **DEVO Functions Library**: https://docs.devo.com/confluence/ndt/latest/searching-data/functions
- **DEVO Community**: https://community.devo.com/

## Need Help?

If you encounter DEVO syntax issues:

1. Check the official DEVO documentation for your platform version
2. Use the DEVO Query Builder interface to explore syntax
3. Consult with your DEVO administrator
4. Review example queries from DEVO's built-in Content Library
5. Open an issue in this repository with your specific syntax question

## Disclaimer

**This guide is based on DEVO LINQ syntax patterns and may not reflect all platform-specific variations.** Always validate queries against your specific DEVO platform version and data source schemas. The queries in this library are **conceptual templates** that require syntax adjustments for production use.

---

**Last Updated**: December 2024
**DEVO Platform Compatibility**: Verify with your platform version
**Feedback**: Please report any syntax patterns or functions we should add to this guide
