"""
===========================================================================
 Juniper Configuration Parser & Report Generator
===========================================================================

This script parses a Juniper SRX firewall configuration exported in 'set' format
(from a .txt file), extracts key configuration elements, and generates a 
comprehensive Excel report with structured tabs for each major category.

Key features:
-------------
- Extracts and categorizes configuration lines into the following tabs:
    • System Settings
    • Interfaces
    • Security Zones
    • Address Book
    • NAT Rules
    • Security Policies
    • BGP/Protocols
    • Static Routes
    • Applications
    • Firewall Filters
    • Raw Config (full unprocessed text)

- Supports multi-line parsing logic for complex rules (e.g., policies, NAT, BGP).
- Outputs a human-readable Excel (.xlsx) file ideal for documentation, audits,
  and firewall review sessions.

Usage:
------
1. Place the Juniper configuration file (e.g., 'juniper_config.txt') in the same folder.
2. Update the `config_file_path` variable if needed.
3. Run the script using Python 3.x.
4. The Excel report will be saved as 'juniper_config_report.xlsx'.

Author: Chinedu Omenkukwu
Date: 2020-04-12
"""

# ===============================================
#    JUNIPER CONFIG PARSER - Report Generator
# ===============================================

import re
import pandas as pd
from collections import defaultdict

# Define the path to the Juniper configuration text file
config_file_path = "juniper_config.txt"  # Change this path as needed

# Read the configuration file
with open(config_file_path, "r") as file:
    config_lines = [line.strip() for line in file if line.startswith("set ")]

# Initialize dictionaries to hold data for each tab
data_tabs = {
    "System_Settings": [],
    "Interfaces": [],
    "Security_Zones": [],
    "Address_Book": [],
    "NAT_Rules": [],
    "Security_Policies": [],
    "BGP_Protocols": [],
    "Static_Routes": [],
    "Applications": [],
    "Firewall_Filters": [],
    "Policy_Statements": []  
}

# =========================================
#           System Settings
# =========================================

system_settings = []

for line in config_lines:
    if not line.startswith("set system "):
        continue

    if "host-name" in line:
        match = re.match(r"set system (\S+ )?host-name (.+)", line)
        if match:
            system_settings.append({"Parameter": "host-name", "Value": match.group(2)})

    elif "services" in line:
        match = re.match(r"set system services (\S+)(?: (.+))?", line)
        if match:
            param = f"service-{match.group(1)}"
            value = (match.group(2) or "").strip()
            system_settings.append({"Parameter": param, "Value": value})

    elif "name-server" in line:
        match = re.match(r"set system name-server (.+)", line)
        if match:
            system_settings.append({"Parameter": "name-server", "Value": match.group(1)})

    elif "ntp server" in line:
        match = re.match(r"set system ntp server (.+)", line)
        if match:
            system_settings.append({"Parameter": "ntp-server", "Value": match.group(1)})

    elif "syslog" in line:
        match = re.match(r"set system syslog (.+)", line)
        if match:
            system_settings.append({"Parameter": "syslog", "Value": match.group(1)})

data_tabs["System_Settings"] = system_settings



# =========================================
#           Interfaces
# =========================================

interfaces_structured = []

for line in config_lines:
    if not line.startswith("set interfaces "):
        continue

    tokens = line.replace("set interfaces ", "").split()
    interface = tokens[0]
    unit = ""
    family = ""
    prop = ""
    value = ""

    if "unit" in tokens:
        unit_index = tokens.index("unit")
        unit = tokens[unit_index + 1]

    if "family" in tokens:
        family_index = tokens.index("family")
        family = tokens[family_index + 1]

    if "family" in tokens:
        prop_tokens = tokens[family_index + 2:]
    elif "unit" in tokens:
        prop_tokens = tokens[unit_index + 2:]
    else:
        prop_tokens = tokens[1:]

    if prop_tokens:
        prop = prop_tokens[0]
        value = " ".join(prop_tokens[1:]) if len(prop_tokens) > 1 else ""

    interfaces_structured.append({
        "Interface": interface,
        "Unit": unit,
        "Family": family,
        "Property": prop,
        "Value": value
    })

data_tabs["Interfaces"] = interfaces_structured




# =========================================
#           Security Zones
# =========================================

security_zones_structured = []

for line in config_lines:
    match = re.match(
        r"set security zones security-zone (\S+) interfaces (\S+) host-inbound-traffic (\S+) (\S+)", line
    )
    if match:
        zone, interface, traffic_type, value = match.groups()
        security_zones_structured.append({
            "Zone Name": zone,
            "Interface": interface,
            "Traffic Type": traffic_type,
            "Value": value
        })

data_tabs["Security_Zones"] = security_zones_structured




# =========================================
#           Address Book
# =========================================

address_book_structured = []

for line in config_lines:
    match_address = re.match(r"set security address-book (\S+) address (\S+) (\S+)", line)
    if match_address:
        parent, name, ip = match_address.groups()
        address_book_structured.append({
            "Type": "address",
            "Name": name,
            "Value": ip,
            "Parent": parent
        })
        continue

    match_set = re.match(r"set security address-book (\S+) address-set (\S+) address (\S+)", line)
    if match_set:
        parent, set_name, address = match_set.groups()
        address_book_structured.append({
            "Type": "address-set",
            "Name": f"{set_name} -> {address}",
            "Value": "",
            "Parent": parent
        })

data_tabs["Address_Book"] = address_book_structured




# =============================
# Structured parsing of Firewall Filters
# =============================

firewall_filters = []
filter_terms = defaultdict(lambda: {
    "Filter": "",
    "Term": "",
    "Matches": defaultdict(list),
    "Action": ""
})

for line in config_lines:
    match = re.match(r"set firewall filter (\S+) term (\S+) (from|then) (\S+)(?: (.+))?", line)
    if match:
        filter_name, term, section, keyword, value = match.groups()
        key = f"{filter_name}:{term}"
        entry = filter_terms[key]
        entry["Filter"] = filter_name
        entry["Term"] = term

        if section == "from":
            entry["Matches"][keyword].append(value or "")
        elif section == "then":
            entry["Action"] = keyword if not value else f"{keyword} {value}"

# Flatten and format into rows
for term_key, entry in filter_terms.items():
    for match_type, values in entry["Matches"].items():
        firewall_filters.append({
            "Filter": entry["Filter"],
            "Term": entry["Term"],
            "Match Type": match_type,
            "Match Value": ", ".join(values),
            "Action": entry["Action"]
        })

data_tabs["Firewall_Filters"] = firewall_filters




# =============================
# Structured parsing of Policy Statements
# =============================

policy_statements = []
current_policy = ""
current_term = ""

for line in config_lines:
    match = re.match(r"set policy-options policy-statement (\S+)(?: term (\S+))? (from|then) (\S+)(?: (.+))?", line)
    if match:
        policy, term, section, keyword, value = match.groups()
        current_policy = policy
        current_term = term or "(default)"
        policy_statements.append({
            "Policy Name": current_policy,
            "Term": current_term,
            "Section": section,
            "Match Type / Action": keyword,
            "Value": value or ""
        })

data_tabs["Policy_Statements"] = policy_statements






# =========================================
#           NAT Rules
# =========================================

nat_structured = []

for line in config_lines:
    if line.startswith("set security nat source pool"):
        parts = line.split()
        if len(parts) >= 6:
            nat_structured.append({
                "Rule Type": "source",
                "Rule Set": "",
                "Rule Name": "",
                "Match Type": "pool",
                "Value": parts[5],
                "Action Type": "address",
                "Action Value": parts[-1]
            })

    elif "rule-set" in line and "rule" in line:
        match = re.match(
            r"set security nat (\S+) rule-set (\S+) rule (\S+) match (\S+) (.+)", line)
        if match:
            rule_type, rule_set, rule_name, match_type, value = match.groups()
            nat_structured.append({
                "Rule Type": rule_type,
                "Rule Set": rule_set,
                "Rule Name": rule_name,
                "Match Type": match_type,
                "Value": value,
                "Action Type": "",
                "Action Value": ""
            })
        else:
            match_action = re.match(
                r"set security nat (\S+) rule-set (\S+) rule (\S+) then (\S+) (.+)", line)
            if match_action:
                rule_type, rule_set, rule_name, action_type, action_value = match_action.groups()
                nat_structured.append({
                    "Rule Type": rule_type,
                    "Rule Set": rule_set,
                    "Rule Name": rule_name,
                    "Match Type": "",
                    "Value": "",
                    "Action Type": action_type,
                    "Action Value": action_value
                })

data_tabs["NAT_Rules"] = nat_structured

# =========================================
#           BGP Protocols
# =========================================

bgp_structured = defaultdict(lambda: {
    "Group Name": "", "Type": "", "Import Policy": "", "Export Policy": "", "Neighbors": []
})

for line in config_lines:
    match = re.match(r"set protocols bgp group (\S+) (type|import|export) (\S+)", line)
    if match:
        group, key, value = match.groups()
        bgp_structured[group]["Group Name"] = group
        bgp_structured[group][f"{key.title()} Policy"] = value

    match_peer = re.match(r"set protocols bgp group (\S+) neighbor (\S+) peer-as (\S+)", line)
    if match_peer:
        group, neighbor, asn = match_peer.groups()
        bgp_structured[group]["Neighbors"].append(f"{neighbor} (AS{asn})")

bgp_rows = []
for group, values in bgp_structured.items():
    bgp_rows.append({
        "Group Name": values["Group Name"],
        "Type": values["Type"],
        "Import Policy": values["Import Policy"],
        "Export Policy": values["Export Policy"],
        "Neighbors": ", ".join(values["Neighbors"])
    })

data_tabs["BGP_Protocols"] = bgp_rows

# =========================================
#           Static Routes
# =========================================

static_routes = []

for line in config_lines:
    match = re.match(r"set routing-options static route (\S+) next-hop (\S+)", line)
    if match:
        destination, next_hop = match.groups()
        static_routes.append({
            "Destination": destination,
            "Next Hop": next_hop
        })

data_tabs["Static_Routes"] = static_routes

# =========================================
#           Applications
# =========================================

applications = defaultdict(lambda: {"Name": "", "Protocol": "", "Destination Port": ""})

for line in config_lines:
    match = re.match(r"set applications application (\S+) protocol (\S+)", line)
    if match:
        name, protocol = match.groups()
        applications[name]["Name"] = name
        applications[name]["Protocol"] = protocol

    elif re.match(r"set applications application (\S+) destination-port (.+)", line):
        name, port = re.findall(r"set applications application (\S+) destination-port (.+)", line)[0]
        applications[name]["Name"] = name
        applications[name]["Destination Port"] = port

data_tabs["Applications"] = list(applications.values())

# =========================================
#           Security Policies
# =========================================

security_policies = defaultdict(lambda: {
    "Name": "", "From": "", "To": "", "Source": [],
    "Destination": [], "Schedule": "always", "Service": [],
    "Action": "", "NAT": ""
})

for line in config_lines:
    match = re.match(
        r"set security policies from-zone (\S+) to-zone (\S+) policy (\S+) (match|then) (\S+)(?: (.+))?",
        line
    )
    if match:
        from_zone, to_zone, policy, section, field, value = match.groups()
        rule = security_policies[policy]
        rule["Name"] = policy
        rule["From"] = from_zone
        rule["To"] = to_zone

        if section == "match":
            if field == "source-address" and value:
                rule["Source"].append(value)
            elif field == "destination-address" and value:
                rule["Destination"].append(value)
            elif field == "application" and value:
                rule["Service"].append(value)
        elif section == "then":
            if field in ["permit", "deny", "reject"]:
                rule["Action"] = field
            elif field == "source-nat" and value:
                rule["NAT"] = value

data_tabs["Security_Policies"] = [
    {
        "Name": r["Name"],
        "From": r["From"],
        "To": r["To"],
        "Source": ", ".join(r["Source"]),
        "Destination": ", ".join(r["Destination"]),
        "Schedule": r["Schedule"],
        "Service": ", ".join(r["Service"]),
        "Action": r["Action"],
        "NAT": r["NAT"]
    }
    for r in security_policies.values()
]

# =============================
# Add raw config text as final sheet
# =============================
raw_config = "\n".join(config_lines)
data_tabs["Raw_Config"] = [{"": line} for line in raw_config.splitlines()]




# =========================================
#           Export to Excel
# =========================================

output_file = "juniper_config_report.xlsx"

with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
    for tab_name, records in data_tabs.items():
        df = pd.DataFrame(records)
        df.to_excel(writer, sheet_name=tab_name[:31], index=False)

print(f"✅ Report saved successfully to: {output_file}")
