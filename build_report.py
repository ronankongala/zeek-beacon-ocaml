#!/usr/bin/env python3
"""
CASE-17 investigation report generator.

Builds phase-6-report/CASE-17_Network_Forensics_Investigation_Report.pdf from the
values confirmed against the committed notebook outputs and screenshots.

Usage:
    pip install reportlab
    python build_report.py

House style for this repo: no em dashes. Use "--" everywhere, including inside
table cells. Ampersands are escaped before they reach Paragraph, otherwise
ReportLab parses "ATT&CK" as an entity and emits "ATT&CK;".
"""

import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# Values that are NOT verified against a committed artifact.
# Both are flagged in the Data Provenance section of the report.
# ---------------------------------------------------------------------------

# http.log is not committed and no screenshot shows the request count. 273 is the
# figure carried in README.md. Confirm with:
#     wc -l ~/case18-zeek-lab/zeek-logs/http.log   # then subtract 8 header lines
HTTP_REQUEST_COUNT = 273

# notebook1 reports total_bytes 30,914 for the 212s connection to 10.4.18.4:445.
# The previous revision of this report said 14KB, which matches neither the
# notebook nor README.md.
SMB_BYTES = "30.9KB"

OUT_DIR = "phase-6-report"
OUT_PATH = os.path.join(
    OUT_DIR, "CASE-17_Network_Forensics_Investigation_Report.pdf"
)

ACCENT = colors.HexColor("#1F3B57")
HEADER_BG = colors.HexColor("#1F3B57")
ROW_ALT = colors.HexColor("#F2F5F8")
GRID = colors.HexColor("#B9C4CF")

styles = getSampleStyleSheet()

TitleStyle = ParagraphStyle(
    "CaseTitle",
    parent=styles["Title"],
    fontName="Helvetica-Bold",
    fontSize=24,
    leading=28,
    textColor=ACCENT,
    spaceAfter=2,
)
SubTitleStyle = ParagraphStyle(
    "CaseSubTitle",
    parent=styles["Normal"],
    fontName="Helvetica",
    fontSize=13,
    leading=17,
    alignment=TA_CENTER,
    textColor=colors.HexColor("#44586B"),
    spaceAfter=18,
)
H1 = ParagraphStyle(
    "H1",
    parent=styles["Heading1"],
    fontName="Helvetica-Bold",
    fontSize=14,
    leading=18,
    textColor=ACCENT,
    spaceBefore=16,
    spaceAfter=8,
)
H2 = ParagraphStyle(
    "H2",
    parent=styles["Heading2"],
    fontName="Helvetica-Bold",
    fontSize=11.5,
    leading=15,
    textColor=colors.HexColor("#2E4C68"),
    spaceBefore=12,
    spaceAfter=6,
)
Body = ParagraphStyle(
    "Body",
    parent=styles["Normal"],
    fontName="Helvetica",
    fontSize=9.5,
    leading=13.5,
    spaceAfter=7,
)
Cell = ParagraphStyle(
    "Cell", parent=Body, fontSize=8.5, leading=11, spaceAfter=0
)
CellHead = ParagraphStyle(
    "CellHead",
    parent=Cell,
    fontName="Helvetica-Bold",
    textColor=colors.white,
)
Mono = ParagraphStyle(
    "Mono",
    parent=styles["Code"],
    fontName="Courier",
    fontSize=7.6,
    leading=9.6,
    leftIndent=10,
    spaceAfter=2,
)
Note = ParagraphStyle(
    "Note",
    parent=Body,
    fontSize=8.5,
    leading=11.5,
    textColor=colors.HexColor("#5A6A79"),
)


def esc(text):
    """Escape XML-significant characters before they reach Paragraph."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def p(text, style=Cell):
    return Paragraph(esc(text), style)


def build_table(header, rows, widths, align_first_left=True):
    """Build a wrapped-cell table. Every cell is a Paragraph so long values wrap
    inside their own column instead of spilling and desynchronising the rows."""
    data = [[Paragraph(esc(h), CellHead) for h in header]]
    for row in rows:
        data.append([p(c) for c in row])

    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), ROW_ALT))
    table.setStyle(TableStyle(style))
    return table


def code_block(lines):
    """Render a code block as one Paragraph with explicit indentation.

    Paragraph collapses leading whitespace, which strips the indentation out of
    YAML. Preformatted keeps it but wraps against an unpredictable width and
    overprinted surrounding text. Converting only the leading spaces to
    non-breaking spaces keeps the indentation and leaves interior spaces
    breakable, so a long line degrades into a wrap instead of an overlap.
    """
    # One table row per source line. A single multi-line Paragraph (or a
    # Preformatted) inherited an unpredictable wrap width here and overprinted
    # neighbouring text; the row-per-line form matches how every other table in
    # this document is built, and those wrap correctly.
    rows = []
    for line in lines:
        stripped = line.lstrip(" ")
        indent = "&nbsp;" * (len(line) - len(stripped))
        rows.append([Paragraph(indent + esc(stripped) or "&nbsp;", Mono)])

    box = Table(rows, colWidths=[W - 0.2 * inch], hAlign="LEFT")
    box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7F9FB")),
                ("BOX", (0, 0), (-1, -1), 0.4, GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 0.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0.5),
            ]
        )
    )
    return [box]


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#7A8794"))
    canvas.drawString(
        0.75 * inch,
        0.5 * inch,
        "CASE-17 | Ronan Kongala | MS Cybersecurity, Northeastern University",
    )
    canvas.drawRightString(
        letter[0] - 0.75 * inch, 0.5 * inch, "Page %d" % doc.page
    )
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------

W = 7.0 * inch


def story():
    s = []

    s.append(Paragraph("CASE-17", TitleStyle))
    s.append(
        Paragraph(
            "Network Forensics Investigation Report<br/>"
            "SSLoad + Cobalt Strike C2 Beacon Analysis",
            SubTitleStyle,
        )
    )

    s.append(
        build_table(
            ["Field", "Value"],
            [
                ["Analyst", "Ronan Kongala"],
                ["Date", "August 28, 2026"],
                ["PCAP Source", "Malware Traffic Analysis -- 2024-04-18"],
                [
                    "Environment",
                    "REMnux Ubuntu 24.04 | Zeek 8.2.1 | RITA v5.1.2 | "
                    "JupyterLab 4.6.3",
                ],
                ["Classification", "TLP:WHITE -- For Educational Use"],
                [
                    "Repository",
                    "github.com/ronankongala/zeek-beacon-ocaml",
                ],
            ],
            [1.5 * inch, W - 1.5 * inch],
        )
    )

    s.append(Paragraph("Executive Summary", H1))
    s.append(
        Paragraph(
            "This report documents the analysis of a real-world malware PCAP "
            "capturing an SSLoad infection with follow-on Cobalt Strike DLL "
            "activity from April 18, 2024. Network traffic from victim host "
            "10.4.18.169 was analyzed using Zeek 8.2.1 for structured log "
            "generation and RITA v5.1.2 for probabilistic beacon scoring. "
            "Analysis confirmed active C2 communication to 85.239.53.219 on "
            "port 80 over HTTP, with 11 recorded connections totalling 5,087 "
            "seconds of connection time across a beacon window of roughly 80 "
            "minutes.",
            Body,
        )
    )
    s.append(
        Paragraph(
            "RITA assigned a beacon score of 0.504 and auto-tagged the traffic "
            "with rare_signature 'SSLoad/1.1'. The mean inter-connection "
            "interval was 477 seconds with a standard deviation of 169 seconds, "
            "a jitter ratio of roughly 35 percent, consistent with a Cobalt "
            "Strike sleep timer configured near 600 seconds. Secondary "
            "suspicious channels included api.openweathermap.org and t.me "
            "(Telegram), both scoring 0.682. Zeek produced 16 structured log "
            "files from the capture. Three Jupyter notebooks document the full "
            "detection methodology across conn.log analysis, DNS query "
            "profiling, and beacon interval visualization.",
            Body,
        )
    )

    # -- 1 --------------------------------------------------------------
    s.append(Paragraph("1. Technical Findings", H1))

    s.append(Paragraph("1.1 Zeek Log Summary", H2))
    s.append(
        Paragraph(
            "Zeek 8.2.1 ran in standalone mode against the PCAP, generating 16 "
            "structured log files totalling 220KB. The presence of "
            "kerberos.log, ldap.log and ldap_search.log alongside C2 traffic "
            "indicates post-exploitation Active Directory activity.",
            Body,
        )
    )
    s.append(
        build_table(
            ["Log File", "Size", "Significance"],
            [
                [
                    "conn.log",
                    "27K",
                    "All connections -- primary beacon detection source",
                ],
                [
                    "http.log",
                    "81K",
                    "%d HTTP requests including SSLoad C2 callbacks"
                    % HTTP_REQUEST_COUNT,
                ],
                [
                    "dns.log",
                    "19K",
                    "73 DNS queries including C2 dead drop domains",
                ],
                [
                    "ssl.log",
                    "12K",
                    "TLS sessions -- Cobalt Strike HTTPS beacon candidates",
                ],
                ["files.log", "8.3K", "DLL payload transfers detected"],
                ["dce_rpc.log", "8.3K", "Remote procedure calls"],
                ["x509.log", "8.1K", "Certificates from observed TLS sessions"],
                ["ldap_search.log", "4.7K", "AD directory search activity"],
                ["ocsp.log", "3.6K", "Certificate revocation checks"],
                ["ldap.log", "2.8K", "AD enumeration activity"],
                ["smb_files.log", "2.5K", "SMB file operations"],
                ["kerberos.log", "2.1K", "AD authentication activity"],
                ["smb_mapping.log", "1.1K", "SMB share mapping"],
                ["pe.log", "597B", "Portable executable metadata"],
                ["weird.log", "405B", "Protocol anomalies"],
                ["packet_filter.log", "278B", "Capture filter record"],
            ],
            [1.35 * inch, 0.65 * inch, W - 2.0 * inch],
        )
    )
    s.append(Spacer(1, 4))
    s.append(
        Paragraph(
            "Sixteen files, 220KB total, as shown in screenshot 03.", Note
        )
    )

    s.append(PageBreak())

    s.append(Paragraph("1.2 C2 Beacon Identification -- conn.log", H2))
    s.append(
        Paragraph(
            "Sorting conn.log by connection duration surfaced 85.239.53.219:80 "
            "as the primary C2 server. Eleven connections were recorded over "
            "approximately 80 minutes. Three connections exceeded 17 minutes in "
            "duration with low originator byte counts, the hallmark of a C2 "
            "beacon with a sleep timer. Connections are listed in "
            "chronological order.",
            Body,
        )
    )
    s.append(
        build_table(
            [
                "Timestamp (Unix)",
                "Duration (s)",
                "Duration (min)",
                "Orig Bytes",
                "State",
            ],
            [
                ["1713465805.964", "1982.689", "33.0", "29,967", "SF"],
                ["1713466385.888", "6.744", "0.1", "118", "RSTO"],
                ["1713466987.722", "6.687", "0.1", "118", "RSTO"],
                ["1713467580.694", "21.689", "0.4", "118", "RSTO"],
                ["1713467808.656", "1992.109", "33.2", "30,071", "SF"],
                ["1713468183.700", "6.667", "0.1", "118", "RSTO"],
                ["1713468783.833", "6.754", "0.1", "118", "RSTO"],
                ["1713469390.769", "6.672", "0.1", "118", "RSTO"],
                ["1713469820.768", "1034.494", "17.2", "15,600", "S1"],
                ["1713469985.748", "13.706", "0.2", "118", "RSTO"],
                ["1713470580.738", "9.769", "0.2", "118", "RSTO"],
            ],
            [1.7 * inch, 1.2 * inch, 1.3 * inch, 1.3 * inch, 1.5 * inch],
        )
    )
    s.append(Spacer(1, 4))
    s.append(
        Paragraph(
            "Connection states are taken from notebook 3's committed output. "
            "Only the two long sessions close cleanly (SF); the 1034s session "
            "is S1 (established, no close seen) and every 118-byte check-in is "
            "RSTO, meaning the responder reset the connection. That reset "
            "pattern is itself characteristic of short beacon polls being torn "
            "down server-side rather than completing a normal exchange.",
            Note,
        )
    )
    s.append(Spacer(1, 8))
    s.append(
        Paragraph(
            "The alternating pattern of long sustained connections and brief "
            "118-byte check-ins indicates the beacon cycling between active "
            "tasking sessions and idle polling.",
            Body,
        )
    )

    s.append(Paragraph("1.3 Beacon Interval Statistics", H2))
    s.append(
        Paragraph(
            "Inter-arrival intervals were computed across the 10 gaps between "
            "the 11 connections.",
            Body,
        )
    )
    s.append(
        build_table(
            ["Statistic", "Value", "Interpretation"],
            [
                [
                    "Mean interval",
                    "477.5 s",
                    "Roughly 8 minutes between callbacks",
                ],
                [
                    "Median interval",
                    "586.4 s",
                    "Sits above the mean; jitter subtracts from a ceiling",
                ],
                [
                    "Standard deviation",
                    "169.2 s",
                    "Spread consistent with a configured jitter value",
                ],
                ["Minimum interval", "165.0 s", "Shortest observed gap"],
                [
                    "Maximum interval",
                    "606.9 s",
                    "Approximates the configured sleep ceiling",
                ],
                [
                    "Jitter ratio",
                    "35.4 %",
                    "Std dev / mean -- typical Cobalt Strike jitter range",
                ],
            ],
            [1.6 * inch, 1.0 * inch, W - 2.6 * inch],
        )
    )
    s.append(Spacer(1, 4))
    s.append(
        Paragraph(
            "Six of the ten intervals fall between 579s and 607s, clustering "
            "just under a 10-minute sleep. The four short intervals (165s to "
            "430s) are the jitter subtracting from that ceiling.",
            Note,
        )
    )

    s.append(Paragraph("1.4 RITA Beacon Scoring Results", H2))
    s.append(
        Paragraph(
            "RITA v5.1.2 scored all external connections for beaconing "
            "regularity. Scores above 0.5 warrant investigation. "
            "85.239.53.219 received the rare_signature:SSLoad/1.1 modifier, "
            "confirming RITA's threat intel feeds identified the SSLoad user "
            "agent in HTTP traffic.",
            Body,
        )
    )
    s.append(
        build_table(
            ["Destination", "Score", "Conns", "Duration", "Severity", "Modifier"],
            [
                ["t.me", "0.682", "9", "190.19 s", "Low", "--"],
                [
                    "api.openweathermap.org",
                    "0.682",
                    "9",
                    "2.17 s",
                    "Low",
                    "--",
                ],
                [
                    "login.microsoftonline.com",
                    "0.590",
                    "7",
                    "6.33 s",
                    "None",
                    "--",
                ],
                [
                    "85.239.53.219",
                    "0.504",
                    "11",
                    "5,087 s",
                    "Low",
                    "rare_signature: SSLoad/1.1",
                ],
                [
                    "settings-win.data.microsoft.com",
                    "0.196",
                    "4",
                    "2.16 s",
                    "None",
                    "--",
                ],
            ],
            [
                1.75 * inch,
                0.55 * inch,
                0.5 * inch,
                0.8 * inch,
                0.7 * inch,
                W - 4.3 * inch,
            ],
        )
    )
    s.append(Spacer(1, 4))
    s.append(
        Paragraph(
            "RITA ranked t.me and api.openweathermap.org higher on raw score "
            "and rated all three Low severity, so score alone does not name the "
            "primary C2. 85.239.53.219 takes that call on three other grounds: "
            "the SSLoad/1.1 rare_signature tag, 2,164,635 bytes transferred "
            "against 12,013 for api.openweathermap.org, and 5,087 seconds of "
            "connection time against a handful of short polls. Nine evenly "
            "spaced DNS lookups score well precisely because regularity is "
            "cheap at low volume.",
            Note,
        )
    )

    s.append(PageBreak())

    s.append(Paragraph("1.5 DNS Analysis", H2))
    s.append(
        Paragraph(
            "dns.log contained 73 queries across 24 unique domains. "
            "wpad.partridgecliff.com was the top queried domain. WPAD queries "
            "indicate the malware probing for proxy configurations to route C2 "
            "through legitimate channels.",
            Body,
        )
    )
    s.append(
        build_table(
            ["Domain", "Count", "Assessment"],
            [
                [
                    "wpad.partridgecliff.com",
                    "17",
                    "WPAD probe -- proxy discovery for C2 evasion",
                ],
                [
                    "api.openweathermap.org",
                    "9",
                    "Suspected dead drop resolver / fallback C2",
                ],
                [
                    "t.me",
                    "9",
                    "Telegram -- suspected exfil or fallback C2 channel",
                ],
                [
                    "login.microsoftonline.com",
                    "7",
                    "Likely legitimate Microsoft authentication",
                ],
                [
                    "v10.events.data.microsoft.com",
                    "4",
                    "Microsoft telemetry -- likely benign",
                ],
                [
                    "partridge-dc.partridgecliff.com",
                    "2",
                    "Domain controller lookup -- AD enumeration",
                ],
            ],
            [2.3 * inch, 0.6 * inch, W - 2.9 * inch],
        )
    )

    # -- 2 --------------------------------------------------------------
    s.append(Paragraph(esc("2. MITRE ATT&CK Mapping"), H1))
    s.append(
        build_table(
            ["Technique", "Name", "Evidence"],
            [
                [
                    "T1071",
                    "Application Layer Protocol",
                    "SSLoad C2 over HTTP port 80; confirmed in http.log",
                ],
                [
                    "T1071.001",
                    "Web Protocols",
                    "TLS sessions in ssl.log -- Cobalt Strike HTTPS beacon",
                ],
                [
                    "T1071.004",
                    "DNS C2",
                    "High-frequency queries to api.openweathermap.org and "
                    "t.me; score 0.682",
                ],
                [
                    "T1008",
                    "Fallback Channels",
                    "t.me and api.openweathermap.org as parallel C2 channels",
                ],
                [
                    "T1557.001",
                    "LLMNR/NBT-NS Poisoning",
                    "wpad.partridgecliff.com top DNS query -- WPAD abuse for "
                    "proxy redirection",
                ],
                [
                    "T1018",
                    "Remote System Discovery",
                    "partridge-dc.partridgecliff.com lookup -- domain "
                    "controller enumeration",
                ],
            ],
            [0.9 * inch, 1.75 * inch, W - 2.65 * inch],
        )
    )

    # -- 3 --------------------------------------------------------------
    s.append(Paragraph("3. Indicators of Compromise", H1))
    s.append(
        build_table(
            ["IOC Type", "Value", "Context"],
            [
                [
                    "IP Address",
                    "85.239.53.219",
                    "SSLoad C2 -- port 80 HTTP -- 11 connections -- beacon "
                    "score 0.504",
                ],
                [
                    "IP Address",
                    "10.4.18.169",
                    "Victim host -- source of all C2 callbacks",
                ],
                [
                    "Domain",
                    "api.openweathermap.org",
                    "Dead drop resolver -- beacon score 0.682 -- 9 connections",
                ],
                [
                    "Domain",
                    "t.me",
                    "Telegram -- fallback C2 -- beacon score 0.682",
                ],
                [
                    "Domain",
                    "wpad.partridgecliff.com",
                    "WPAD probe -- highest DNS query count (17)",
                ],
                [
                    "Domain",
                    "partridge-dc.partridgecliff.com",
                    "Domain controller -- AD enumeration target",
                ],
                [
                    "User Agent",
                    "SSLoad/1.1",
                    "SSLoad malware HTTP user agent -- flagged by RITA "
                    "rare_signature",
                ],
                ["Port", "80/tcp", "Primary C2 port -- plaintext HTTP"],
                [
                    "Port",
                    "445/tcp",
                    "Single SMB connection to internal host 10.4.18.4 "
                    "(212s, %s, state S1) -- warrants investigation" % SMB_BYTES,
                ],
                [
                    "Beacon Interval",
                    "477 seconds",
                    "Mean inter-connection interval -- Cobalt Strike sleep "
                    "timer",
                ],
                [
                    "Beacon Jitter",
                    "~35%",
                    "Std deviation ~169s -- Cobalt Strike jitter configuration",
                ],
                [
                    "File Type",
                    "DLL",
                    "Cobalt Strike beacon delivered as DLL (files.log 8.3KB)",
                ],
            ],
            [1.15 * inch, 2.0 * inch, W - 3.15 * inch],
        )
    )

    s.append(PageBreak())

    # -- 4 --------------------------------------------------------------
    s.append(Paragraph("4. Detection Recommendations", H1))

    s.append(Paragraph("4.1 Zeek + RITA Deployment", H2))
    s.append(
        Paragraph(
            "Deploy Zeek as a network tap on the perimeter or at east-west "
            "chokepoints to generate structured TSV logs. Feed logs to RITA on "
            "a rolling 24-hour import schedule. Alert on any beacon score above "
            "0.5 for analyst review. The rare_signature modifier provides "
            "automatic malware family tagging when known user agents appear in "
            "HTTP traffic.",
            Body,
        )
    )
    s.extend(
        code_block(
            [
                "rita import --database daily --rolling \\",
                "     --logs /path/to/zeek/logs",
            ]
        )
    )

    s.append(Paragraph("4.2 Sigma Rules", H2))
    s.extend(
        code_block(
            [
                "title: SSLoad C2 Beacon via HTTP",
                "id: case18-001",
                "status: experimental",
                "description: Detects SSLoad C2 via long-duration low-byte HTTP connections",
                "logsource:",
                "    product: zeek",
                "    service: conn",
                "detection:",
                "    selection:",
                "        proto: tcp",
                "        id.resp_p: 80",
                "        duration|gt: 600",
                "        orig_bytes|lt: 5000",
                "    condition: selection",
                "level: high",
                "tags:",
                "    - attack.t1071",
            ]
        )
    )
    s.append(Spacer(1, 8))
    s.extend(
        code_block(
            [
                "title: High-Frequency DNS to Non-Corporate Domain",
                "id: case18-002",
                "status: experimental",
                "description: Detects repeated DNS queries suggesting DGA or C2 dead drop",
                "logsource:",
                "    product: zeek",
                "    service: dns",
                "detection:",
                "    selection:",
                "        qtype_name: A",
                "    timeframe: 10m",
                "    condition: selection | count(query) by query > 8",
                "level: medium",
                "tags:",
                "    - attack.t1071.004",
            ]
        )
    )

    # Deliberately not wrapped in KeepTogether: doing so rendered the header row
    # one line out of step with the first column. A PageBreak above keeps the
    # table whole instead.
    s.append(PageBreak())
    s.append(Paragraph("4.3 Network Controls", H2))
    s.append(Spacer(1, 8))
    s.append(
        build_table(
            ["Control", "Implementation"],
            [
                [
                    "Block WPAD externally",
                    "DNS firewall rule blocking wpad.* lookups leaving the "
                    "network perimeter",
                ],
                [
                    "Restrict Telegram egress",
                    "Block t.me and *.t.me at the proxy layer -- not a "
                    "legitimate business application",
                ],
                [
                    "Monitor port 80 outbound",
                    "Alert on connections longer than 10 minutes over plain "
                    "HTTP to non-whitelisted IPs",
                ],
                [
                    "RITA rolling import",
                    "Automate daily Zeek log ingestion; page on any beacon "
                    "score above 0.5",
                ],
                [
                    "User agent inspection",
                    "Deploy HTTP inspection at the proxy to alert on unknown "
                    "or rare user agent strings",
                ],
                [
                    "SMB monitoring",
                    "Alert on SMB connections to unexpected internal hosts",
                ],
            ],
            [2.4 * inch, W - 2.4 * inch],
        )
    )

    # -- 5 --------------------------------------------------------------
    s.append(Paragraph("5. Analysis Methodology", H1))
    s.append(
        build_table(
            ["Phase", "Tool", "Output"],
            [
                [
                    "1 -- Environment Setup",
                    "Zeek 8.2.1, RITA v5.1.2, JupyterLab 4.6.3",
                    "Lab on REMnux Ubuntu 24.04",
                ],
                [
                    "2 -- PCAP Acquisition",
                    "wget, unzip",
                    "SSLoad + Cobalt Strike PCAP (6.4MB, MTA 2024-04-18)",
                ],
                [
                    "3 -- Log Generation",
                    "zeek -r pcapfile",
                    "16 structured log files (220KB total)",
                ],
                [
                    "4 -- Beacon Scoring",
                    "rita import, rita view",
                    "Beacon scores for all external connections",
                ],
                [
                    "5 -- Threat Hunting",
                    "Jupyter + pandas + matplotlib",
                    "3 notebooks: conn, DNS, beacon interval analysis",
                ],
                [
                    "6 -- Reporting",
                    "Python ReportLab",
                    "This PDF -- ATT&CK mapped, IOC table, detection rules",
                ],
            ],
            [1.6 * inch, 2.2 * inch, W - 3.8 * inch],
        )
    )

    # -- 6 --------------------------------------------------------------
    s.append(Paragraph("6. Data Provenance", H1))
    s.append(
        Paragraph(
            "Every figure in this report traces to a committed artifact in the "
            "repository, with the exceptions noted below.",
            Body,
        )
    )
    s.append(
        build_table(
            ["Figure", "Source", "Status"],
            [
                [
                    "Beacon score 0.504, 11 conns, 5,087s, rare_signature",
                    "screenshot 06 (raw RITA output)",
                    "Verified",
                ],
                [
                    "Interval statistics (477.5s mean, 169.2s std, 35.4%)",
                    "notebook3 committed output",
                    "Verified",
                ],
                [
                    "Connection table incl. states",
                    "notebook3 committed output",
                    "Verified",
                ],
                [
                    "16 Zeek logs, 220KB, per-file sizes",
                    "screenshot 03",
                    "Verified",
                ],
                ["73 DNS queries, per-domain counts", "notebook2", "Verified"],
                [
                    "SMB connection to 10.4.18.4 (212s, %s)" % SMB_BYTES,
                    "notebook1 top-15 table",
                    "Verified",
                ],
                [
                    "%d HTTP requests" % HTTP_REQUEST_COUNT,
                    "http.log (not committed)",
                    "Unverified -- confirm with wc -l on http.log less 8 "
                    "header lines",
                ],
            ],
            [2.5 * inch, 1.8 * inch, W - 4.3 * inch],
        )
    )

    # -- 7 --------------------------------------------------------------
    s.append(Paragraph("7. References", H1))
    for ref in [
        "Malware Traffic Analysis 2024-04-18: "
        "malware-traffic-analysis.net/2024/04/18/",
        "MITRE ATT&CK T1071: attack.mitre.org/techniques/T1071/",
        "MITRE ATT&CK T1071.001: attack.mitre.org/techniques/T1071/001/",
        "MITRE ATT&CK T1071.004: attack.mitre.org/techniques/T1071/004/",
        "MITRE ATT&CK T1008: attack.mitre.org/techniques/T1008/",
        "MITRE ATT&CK T1557.001: attack.mitre.org/techniques/T1557/001/",
        "MITRE ATT&CK T1018: attack.mitre.org/techniques/T1018/",
        "RITA v5 Repository: github.com/activecm/rita",
        "Zeek Network Security Monitor: zeek.org",
        "Lab Repository: github.com/ronankongala/zeek-beacon-ocaml",
    ]:
        s.append(Paragraph("- " + esc(ref), Body))

    return s


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    doc = SimpleDocTemplate(
        OUT_PATH,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="CASE-17 Network Forensics Investigation Report",
        author="Ronan Kongala",
        subject="SSLoad + Cobalt Strike C2 Beacon Analysis",
    )
    doc.build(story(), onFirstPage=footer, onLaterPages=footer)
    print("Wrote %s" % OUT_PATH)


if __name__ == "__main__":
    main()
