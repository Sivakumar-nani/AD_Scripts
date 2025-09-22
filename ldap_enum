#!/bin/bash
# ldap_enum_html.sh
# Full AD enumeration with ldapsearch and HTML output
# Usage: ./ldap_enum_html.sh --dc-ip <DC_IP> -u <USER> -p <PASS> --domain <DOMAIN>

# ===== Default values =====
DC_IP=""
USER=""
PASS=""
DOMAIN=""

# ===== Help =====
print_help() {
    cat << EOF
Usage: $0 --dc-ip <DC_IP> -u <USER> -p <PASS> --domain <DOMAIN>
Options:
  --dc-ip      Domain Controller IP
  -u           Username
  -p           Password
  --domain     Domain name
  -h, --help   Show this help menu
Example:
  $0 --dc-ip 10.10.10.12 -u attacker.user -p MyPassword123 --domain example.com
EOF
}

# ===== Parse arguments =====
while [[ $# -gt 0 ]]; do
    case $1 in
        --dc-ip) DC_IP="$2"; shift 2 ;;
        -u) USER="$2"; shift 2 ;;
        -p) PASS="$2"; shift 2 ;;
        --domain) DOMAIN="$2"; shift 2 ;;
        -h|--help) print_help; exit 0 ;;
        *) echo "Unknown option $1"; print_help; exit 1 ;;
    esac
done

# ===== Validate mandatory arguments =====
if [[ -z "$DC_IP" || -z "$USER" || -z "$PASS" || -z "$DOMAIN" ]]; then
    echo "Error: All parameters are required."
    print_help
    exit 1
fi

# ===== HTML report =====
REPORT_FILE="ldap_enum_report.html"
cat > $REPORT_FILE <<EOF
<html>
<head>
<title>LDAP Enumeration Report</title>
<style>
body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
th { background-color: #4CAF50; color: white; }
tr:nth-child(even) { background-color: #f9f9f9; }
h2 { color: #333; }
.priv { background-color: #ffcccc; } /* highlight privileged */
</style>
</head>
<body>
<h1>LDAP Enumeration Report</h1>
EOF

# ===== Base DN =====
BASE_DN=$(ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" -s base -b "" defaultNamingContext -LLL | grep "^defaultNamingContext:" | awk '{print $2}')
if [[ -z "$BASE_DN" ]]; then
    echo "Failed to retrieve Base DN."
    exit 1
fi

# ===== Domain Info =====
echo "<h2>Domain Info</h2><table><tr><th>Attribute</th><th>Value</th></tr>" >> $REPORT_FILE
USEFUL_ATTRS="dn name objectClass distinguishedName whenCreated whenChanged subRefs maxPwdAge minPwdLength pwdProperties rIDManagerReference fSMORoleOwner msDS-Behavior-Version dc"
for attr in $USEFUL_ATTRS; do
    VAL=$(ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" -b "$BASE_DN" -s base -LLL $attr | grep "^$attr:" | sed "s/^$attr: //")
    echo "<tr><td>$attr</td><td>$VAL</td></tr>" >> $REPORT_FILE
done
echo "</table>" >> $REPORT_FILE

# ===== Users =====
echo "<h2>Users</h2><table><tr><th>CN</th><th>Description</th><th>Roles / Groups</th><th>Admin</th><th>Last Logon</th><th>Pwd Flags</th><th>Email / ProxyAddresses</th></tr>" >> $REPORT_FILE
ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" -b "$BASE_DN" "(&(objectClass=user)(!(objectClass=computer)))" cn description memberOf adminCount lastLogon userAccountControl mail proxyAddresses -LLL | \
awk '
/^cn: /{cn=$2}
/^description: /{desc=$0}
/^memberOf: /{member=(member?member"\n"$0:$0)}
/^adminCount: /{admin=$0}
/^lastLogon: /{logon=$0}
/^userAccountControl: /{uac=$0}
/^mail: /{mail=$0}
/^proxyAddresses: /{proxy=(proxy?proxy"\n"$0:$0)}
/^$/{
  priv=admin? "priv":"";
  print "<tr class=\""priv"\"><td>"cn"</td><td>"desc"</td><td>"member"</td><td>"admin"</td><td>"logon"</td><td>"uac"</td><td>"mail"<br>"proxy"</td></tr>";
  cn=desc=member=admin=logon=uac=mail=proxy=""
}' >> $REPORT_FILE
echo "</table>" >> $REPORT_FILE

# ===== Computers =====
echo "<h2>Computers</h2><table><tr><th>CN</th><th>OS</th><th>Last Logon</th><th>Groups</th></tr>" >> $REPORT_FILE
ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" -b "$BASE_DN" "(objectClass=computer)" cn operatingSystem lastLogon memberOf -LLL | \
awk '
/^cn: /{cn=$2}
/^operatingSystem: /{os=$0}
/^lastLogon: /{logon=$0}
/^memberOf: /{group=(group?group"\n"$0:$0)}
/^$/{
  print "<tr><td>"cn"</td><td>"os"</td><td>"logon"</td><td>"group"</td></tr>";
  cn=os=logon=group=""
}' >> $REPORT_FILE
echo "</table>" >> $REPORT_FILE

# ===== Groups =====
echo "<h2>Groups</h2><table><tr><th>CN</th><th>Members</th><th>Nested</th><th>Privileged</th></tr>" >> $REPORT_FILE
ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" -b "$BASE_DN" "(objectClass=group)" cn member adminCount -LLL | \
awk '
/^cn: /{cn=$2}
/^member: /{member=(member?member"\n"$0:$0)}
/^adminCount: /{admin=$0}
/^$/{
  priv=admin? "priv":"";
  print "<tr class=\""priv"\"><td>"cn"</td><td>"member"</td><td>"member"</td><td>"admin"</td></tr>";
  cn=member=admin=""
}' >> $REPORT_FILE
echo "</table>" >> $REPORT_FILE

# ===== Organizational Units =====
echo "<h2>Organizational Units</h2><table><tr><th>OU</th></tr>" >> $REPORT_FILE
ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" -b "$BASE_DN" "(objectClass=organizationalUnit)" ou -LLL | \
awk '/^ou: /{print "<tr><td>"$2"</td></tr>"}' >> $REPORT_FILE
echo "</table>" >> $REPORT_FILE

# ===== Domain Admins / Enterprise Admins / Schema Admins =====
for group in "Domain Admins" "Enterprise Admins" "Schema Admins"; do
    echo "<h2>$group Members</h2><table><tr><th>CN</th><th>DN</th></tr>" >> $REPORT_FILE
    ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" -b "$BASE_DN" "(&(objectClass=group)(cn=$group))" member -LLL | \
    awk '/^member: /{print "<tr><td>"$2"</td><td>"$2"</td></tr>"}' >> $REPORT_FILE
    echo "</table>" >> $REPORT_FILE
done

# ===== Service Accounts / Special Accounts =====
echo "<h2>Service / Special Accounts</h2><table><tr><th>CN</th><th>Description</th><th>Account Type</th></tr>" >> $REPORT_FILE
ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" -b "$BASE_DN" "(&(objectClass=user)(servicePrincipalName=*))" cn description userAccountControl -LLL | \
awk '
/^cn: /{cn=$2}
/^description: /{desc=$0}
/^userAccountControl: /{uac=$0}
/^$/{
  print "<tr><td>"cn"</td><td>"desc"</td><td>"uac"</td></tr>";
  cn=desc=uac=""
}' >> $REPORT_FILE
echo "</table>" >> $REPORT_FILE

# ===== FSMO Roles =====
echo "<h2>FSMO Roles</h2><table><tr><th>Role</th><th>Holder</th></tr>" >> $REPORT_FILE
ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" -b "$BASE_DN" fSMORoleOwner -LLL | \
awk '/^fSMORoleOwner: /{print "<tr><td>FSMO</td><td>"$2"</td></tr>"}' >> $REPORT_FILE
echo "</table>" >> $REPORT_FILE

# ===== End HTML =====
echo "</body></html>" >> $REPORT_FILE

echo "LDAP enumeration completed. Report saved to $REPORT_FILE"
