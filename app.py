import streamlit as st
import io
import json
import os
import html
import tempfile
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from streamlit_card import card
from streamlit_extras.colored_header import colored_header
from streamlit_extras.metric_cards import style_metric_cards
from heuristics import analyze_email_for_phishing
from email_parser import parse_eml_file

# Set page config - MUST be the first Streamlit command
st.set_page_config(
    page_title="Phishing Email Analyzer",
    page_icon="📧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main .block-container {
        padding-top: 2rem;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #f0f2f6;
        border-radius: 4px 4px 0px 0px;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #4CAF50 !important;
        color: white !important;
    }
    div[data-testid="stMetricValue"] {
        font-size: 28px;
    }
    .risk-high {
        background-color: #ffebee;
        border-left: 5px solid #f44336;
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 20px;
    }
    .risk-medium {
        background-color: #fff8e1;
        border-left: 5px solid #ffa726;
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 20px;
    }
    .risk-low {
        background-color: #e8f5e9;
        border-left: 5px solid #4caf50;
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 20px;
    }
    .finding-card {
        background-color: #f5f5f5;
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 10px;
        border-left: 5px solid #2196f3;
    }
    .header-section {
        background-color: #e3f2fd;
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 15px;
    }
    .big-number {
        font-size: 36px;
        font-weight: bold;
        text-align: center;
    }
    .metric-label {
        font-size: 14px;
        text-align: center;
        color: #616161;
    }
    .highlight-box {
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 10px;
    }
    .highlight-box.red {
        background-color: #ffebee;
        border: 1px solid #ffcdd2;
    }
    .highlight-box.orange {
        background-color: #fff3e0;
        border: 1px solid #ffe0b2;
    }
    .highlight-box.green {
        background-color: #e8f5e9;
        border: 1px solid #c8e6c9;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/000000/security-shield-green.png", width=80)
    st.title("Phishing Analyzer")
    st.markdown("---")
    st.markdown("""
    ### How to use:
    1. Upload an email file (.eml)
    2. View the analysis results
    3. Download a detailed PDF report
    """)
    st.markdown("---")
    st.info("This tool analyzes emails for phishing indicators using multiple heuristics.")

# Main content
colored_header(
    label="📧 Advanced Phishing Email Analyzer",
    description="Upload an email file to analyze it for phishing indicators",
    color_name="green-70"
)

uploaded_file = st.file_uploader("Upload a .eml file", type=["eml"])

# Function to generate PDF report
def generate_pdf_report(parsed_email, results):
    # Create a temporary file
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    temp_filename = temp_file.name
    temp_file.close()

    # Create the PDF document
    doc = SimpleDocTemplate(temp_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Add title
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.darkblue,
        spaceAfter=12
    )
    elements.append(Paragraph("Phishing Analysis Report", title_style))
    elements.append(Spacer(1, 0.25*inch))

    # Add date and time
    date_style = ParagraphStyle(
        'Date',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.gray
    )
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", date_style))
    elements.append(Spacer(1, 0.25*inch))

    # Add email details
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.darkblue,
        spaceAfter=6
    )
    elements.append(Paragraph("Email Details", section_style))

    # Email metadata table
    email_data = [
        ["Subject", parsed_email.get('subject', 'N/A')],
        ["From", parsed_email.get('from', 'N/A')],
        ["To", parsed_email.get('to', 'N/A')],
        ["Date", parsed_email.get('Headers', {}).get('Date', 'N/A')]
    ]

    email_table = Table(email_data, colWidths=[1.5*inch, 5*inch])
    email_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.darkblue),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(email_table)
    elements.append(Spacer(1, 0.25*inch))

    # Risk Score
    elements.append(Paragraph("Risk Assessment", section_style))
    risk_score = results.get('risk_score', 0)
    risk_color = colors.red if risk_score >= 70 else colors.orange if risk_score >= 40 else colors.green
    risk_text = f"Risk Score: {risk_score}/100"
    risk_assessment = "High Risk - Likely Phishing" if risk_score >= 70 else \
                     "Medium Risk - Suspicious" if risk_score >= 40 else \
                     "Low Risk - Probably Safe"

    risk_style = ParagraphStyle(
        'Risk',
        parent=styles['Normal'],
        fontSize=12,
        textColor=risk_color,
        fontName='Helvetica-Bold'
    )
    elements.append(Paragraph(risk_text, risk_style))
    elements.append(Paragraph(risk_assessment, risk_style))
    elements.append(Spacer(1, 0.25*inch))

    # Phishing Indicators
    elements.append(Paragraph("Phishing Indicators", section_style))

    # Spoofed Headers
    if results.get('header_flags'):
        elements.append(Paragraph("Spoofed Headers", styles["Heading3"]))
        header_data = [["Spoofed Header Detected"]]
        for flag in results.get('header_flags', []):
            header_data.append([flag])

        header_table = Table(header_data, colWidths=[6.5*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightcoral),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 0.15*inch))

    # Link Mismatches
    if results.get('link_mismatches'):
        elements.append(Paragraph("Link Mismatches", styles["Heading3"]))
        link_data = [["Display Text", "Actual URL"]]
        for link in results.get('link_mismatches', []):
            link_data.append([link.get('display_text', ''), link.get('actual_url', '')])

        link_table = Table(link_data, colWidths=[3*inch, 3.5*inch])
        link_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightcoral),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(link_table)
        elements.append(Spacer(1, 0.15*inch))

    # Suspicious Domains
    if results.get('suspicious_domains'):
        elements.append(Paragraph("Suspicious Lookalike Domains", styles["Heading3"]))
        domain_data = [["Suspicious Domain", "Similar To", "Similarity"]]
        for domain in results.get('suspicious_domains', []):
            similarity = "High" if domain.get('distance', 5) <= 1 else \
                        "Medium" if domain.get('distance', 5) <= 2 else "Low"
            domain_data.append([
                domain.get('suspicious_domain', ''),
                domain.get('similar_to', ''),
                similarity
            ])

        domain_table = Table(domain_data, colWidths=[2.5*inch, 2*inch, 2*inch])
        domain_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightcoral),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(domain_table)

    # Add disclaimer
    elements.append(Spacer(1, 0.5*inch))
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.grey
    )
    elements.append(Paragraph("Disclaimer: This report is generated automatically and should be reviewed by a security professional. "
                             "False positives may occur.", disclaimer_style))

    # Build the PDF
    doc.build(elements)

    return temp_filename

# Main app logic
if uploaded_file:
    with st.spinner("Analyzing email for phishing indicators..."):
        # Parse the email
        parsed = parse_eml_file(uploaded_file)

        # Analyze for phishing
        results = analyze_email_for_phishing(parsed)

        # Display results in tabs
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🔍 Detailed Analysis", "📧 Email Content", "📄 Raw Headers"])

        with tab1:
            # Overview tab with summary and risk score
            risk_score = results.get('risk_score', 0)
            risk_class = "risk-high" if risk_score >= 70 else "risk-medium" if risk_score >= 40 else "risk-low"
            risk_emoji = "🔴" if risk_score >= 70 else "🟠" if risk_score >= 40 else "🟢"
            risk_text = "High Risk - Likely Phishing" if risk_score >= 70 else \
                       "Medium Risk - Suspicious" if risk_score >= 40 else \
                       "Low Risk - Probably Safe"
            risk_action = "Urgent action required" if risk_score >= 70 else \
                         "Caution recommended" if risk_score >= 40 else \
                         "Appears legitimate"

            # Risk assessment at the top for immediate visibility
            st.markdown(f"<div class='{risk_class}'><h2>{risk_emoji} {risk_text}</h2><p>{risk_action}</p></div>", unsafe_allow_html=True)

            # Email metadata in a cleaner format
            st.markdown("<div class='header-section'>", unsafe_allow_html=True)
            st.subheader("Email Information")
            cols = st.columns(3)
            with cols[0]:
                sender = parsed.get('from', 'Unknown')
                st.markdown(f"**From:** {html.escape(sender)}")
            with cols[1]:
                subject = parsed.get('subject', 'No Subject')
                st.markdown(f"**Subject:** {html.escape(subject)}")
            with cols[2]:
                date = parsed.get('Headers', {}).get('Date', 'Unknown')
                st.markdown(f"**Date:** {html.escape(date)}")
            st.markdown("</div>", unsafe_allow_html=True)

            # Key metrics in visual format
            st.subheader("Threat Indicators")
            metric_cols = st.columns(3)

            # Count the findings
            header_count = len(results.get('header_flags', []))
            link_count = len(results.get('link_mismatches', []))
            domain_count = len(results.get('suspicious_domains', []))

            with metric_cols[0]:
                header_color = "red" if header_count > 0 else "green"
                st.markdown(f"<div class='highlight-box {header_color}'>", unsafe_allow_html=True)
                st.markdown(f"<div class='big-number'>{header_count}</div>", unsafe_allow_html=True)
                st.markdown(f"<div class='metric-label'>Spoofed Headers</div>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            with metric_cols[1]:
                link_color = "red" if link_count > 0 else "green"
                st.markdown(f"<div class='highlight-box {link_color}'>", unsafe_allow_html=True)
                st.markdown(f"<div class='big-number'>{link_count}</div>", unsafe_allow_html=True)
                st.markdown(f"<div class='metric-label'>Mismatched Links</div>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            with metric_cols[2]:
                domain_color = "red" if domain_count > 0 else "green"
                st.markdown(f"<div class='highlight-box {domain_color}'>", unsafe_allow_html=True)
                st.markdown(f"<div class='big-number'>{domain_count}</div>", unsafe_allow_html=True)
                st.markdown(f"<div class='metric-label'>Suspicious Domains</div>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            # Risk score visualization
            st.subheader("Risk Assessment")
            score_cols = st.columns([1, 3])
            with score_cols[0]:
                st.metric("Risk Score", f"{risk_score}/100")
                style_metric_cards()
            with score_cols[1]:
                # Create a progress bar for risk score
                st.progress(risk_score/100)
                st.caption(f"A score of {risk_score} indicates {risk_text.lower()}")

            # Summary of findings
            if header_count > 0 or link_count > 0 or domain_count > 0:
                st.subheader("Key Findings")
                if header_count > 0:
                    with st.expander(f"📬 Found {header_count} spoofed header{'s' if header_count > 1 else ''}", expanded=True):
                        for flag in results.get('header_flags', []):
                            st.warning(html.escape(flag))

                if link_count > 0:
                    with st.expander(f"⚠️ Found {link_count} mismatched link{'s' if link_count > 1 else ''}", expanded=True):
                        for link in results.get('link_mismatches', []):
                            st.error(f"Display text: {link.get('display_text')} → Actual URL: {link.get('actual_url')}")

                if domain_count > 0:
                    with st.expander(f"🚩 Found {domain_count} suspicious domain{'s' if domain_count > 1 else ''}", expanded=True):
                        for domain in results.get('suspicious_domains', []):
                            st.error(f"Suspicious: {domain.get('suspicious_domain')} - Similar to: {domain.get('similar_to')}")
            else:
                st.success("No suspicious indicators found in this email.")

        with tab2:
            # Detailed analysis tab with more visual explanations
            st.subheader("Detailed Phishing Analysis")

            # Explanation section
            st.markdown("""
            <div style='background-color: #e8f4f8; padding: 15px; border-radius: 5px; margin-bottom: 20px;'>
            <h4>Understanding the Analysis</h4>
            <p>This detailed analysis examines three key indicators of phishing:</p>
            <ul>
                <li><strong>Spoofed Headers</strong>: Inconsistencies in email headers that may indicate the sender is not who they claim to be.</li>
                <li><strong>Link Mismatches</strong>: Links that display one URL but actually lead to a different website.</li>
                <li><strong>Suspicious Domains</strong>: Domain names that look similar to legitimate ones but have subtle differences.</li>
            </ul>
            </div>
            """, unsafe_allow_html=True)

            # Header Analysis Section
            st.markdown("### 1. Header Analysis")
            if results.get('header_flags'):
                st.markdown("<div style='background-color: #ffebee; padding: 15px; border-radius: 5px; margin-bottom: 20px;'>", unsafe_allow_html=True)
                st.markdown("#### ⚠️ Suspicious Headers Detected")
                st.markdown("<p>The following inconsistencies were found in the email headers:</p>", unsafe_allow_html=True)

                # Create a more structured display of header issues
                for i, flag in enumerate(results.get('header_flags', [])):
                    st.markdown(f"<div style='background-color: white; padding: 10px; border-left: 4px solid #f44336; margin-bottom: 10px;'>"
                                f"<strong>Issue {i+1}:</strong> {html.escape(flag)}</div>", unsafe_allow_html=True)

                st.markdown("<p><strong>What this means:</strong> The email headers contain inconsistencies that are commonly "
                            "associated with phishing attempts. The sender may be attempting to disguise their true identity.</p>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)
            else:
                st.markdown("<div style='background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin-bottom: 20px;'>", unsafe_allow_html=True)
                st.markdown("#### ✅ Headers Appear Legitimate")
                st.markdown("<p>No inconsistencies were found in the email headers.</p>", unsafe_allow_html=True)
                st.markdown("<p><strong>What this means:</strong> The email headers are consistent with what would be expected from a legitimate sender.</p>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            # Link Analysis Section
            st.markdown("### 2. Link Analysis")
            if results.get('link_mismatches'):
                st.markdown("<div style='background-color: #ffebee; padding: 15px; border-radius: 5px; margin-bottom: 20px;'>", unsafe_allow_html=True)
                st.markdown("#### ⚠️ Deceptive Links Detected")
                st.markdown("<p>The following links in the email are deceptive:</p>", unsafe_allow_html=True)

                # Create a table for link mismatches
                link_data = []
                for link in results.get('link_mismatches', []):
                    link_data.append([link.get('display_text', ''), link.get('actual_url', '')])

                # Display as a dataframe for better readability
                if link_data:
                    df = pd.DataFrame(link_data, columns=["What You See", "Where It Actually Goes"])
                    st.dataframe(df, use_container_width=True)

                st.markdown("<p><strong>What this means:</strong> The email contains links that appear to go to one website but actually "
                            "redirect to a different site. This is a common phishing tactic used to trick users into visiting malicious websites.</p>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)
            else:
                st.markdown("<div style='background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin-bottom: 20px;'>", unsafe_allow_html=True)
                st.markdown("#### ✅ Links Appear Legitimate")
                st.markdown("<p>No deceptive links were found in the email.</p>", unsafe_allow_html=True)
                st.markdown("<p><strong>What this means:</strong> The links in the email accurately represent their destinations.</p>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            # Domain Analysis Section
            st.markdown("### 3. Domain Analysis")
            if results.get('suspicious_domains'):
                st.markdown("<div style='background-color: #ffebee; padding: 15px; border-radius: 5px; margin-bottom: 20px;'>", unsafe_allow_html=True)
                st.markdown("#### ⚠️ Lookalike Domains Detected")
                st.markdown("<p>The following suspicious domains were found:</p>", unsafe_allow_html=True)

                # Create a more visual representation of domain similarities
                for domain in results.get('suspicious_domains', []):
                    suspicious = html.escape(domain.get('suspicious_domain', ''))
                    legitimate = html.escape(domain.get('similar_to', ''))
                    distance = domain.get('distance', 0)

                    similarity = "High" if distance <= 1 else "Medium" if distance <= 2 else "Low"
                    similarity_color = "#f44336" if distance <= 1 else "#ff9800" if distance <= 2 else "#ffc107"

                    st.markdown(f"<div style='background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 10px;'>"
                                f"<p><strong>Suspicious domain:</strong> {suspicious}</p>"
                                f"<p><strong>Mimicking:</strong> {legitimate}</p>"
                                f"<p><strong>Similarity:</strong> <span style='color: {similarity_color};'>{similarity}</span></p>"
                                f"</div>", unsafe_allow_html=True)

                st.markdown("<p><strong>What this means:</strong> The email contains domains that are designed to look similar to legitimate domains. "
                            "This is a common tactic used in phishing to make malicious websites appear trustworthy.</p>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)
            else:
                st.markdown("<div style='background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin-bottom: 20px;'>", unsafe_allow_html=True)
                st.markdown("#### ✅ No Suspicious Domains")
                st.markdown("<p>No lookalike or suspicious domains were detected.</p>", unsafe_allow_html=True)
                st.markdown("<p><strong>What this means:</strong> The domains used in this email do not appear to be mimicking legitimate domains.</p>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            # Recommendations section
            risk_score = results.get('risk_score', 0)
            if risk_score >= 70:
                st.markdown("### 🛡️ Security Recommendations")
                st.markdown("<div style='background-color: #ffebee; padding: 15px; border-radius: 5px; margin-bottom: 20px;'>", unsafe_allow_html=True)
                st.markdown("<h4>⚠️ High Risk - Recommended Actions:</h4>", unsafe_allow_html=True)
                st.markdown("""
                <ul>
                    <li><strong>Do not</strong> click any links in this email</li>
                    <li><strong>Do not</strong> reply to this email</li>
                    <li><strong>Do not</strong> download any attachments</li>
                    <li>Report this email as phishing to your IT department</li>
                    <li>Delete this email from your inbox</li>
                </ul>
                """, unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)
            elif risk_score >= 40:
                st.markdown("### 🛡️ Security Recommendations")
                st.markdown("<div style='background-color: #fff8e1; padding: 15px; border-radius: 5px; margin-bottom: 20px;'>", unsafe_allow_html=True)
                st.markdown("<h4>⚠️ Medium Risk - Recommended Actions:</h4>", unsafe_allow_html=True)
                st.markdown("""
                <ul>
                    <li>Exercise caution with this email</li>
                    <li>Verify the sender through another communication channel before taking any action</li>
                    <li>Do not click links unless you're certain they're legitimate</li>
                    <li>Consider reporting this email to your IT department</li>
                </ul>
                """, unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

        with tab3:
            # Email content tab
            st.subheader("Email Body")
            if parsed.get('Body'):
                st.code(parsed.get('Body'), language="html")
            else:
                st.info("No email body content available")

        with tab4:
            # Raw headers tab
            st.subheader("Raw Email Headers")
            st.json(parsed.get('Headers', {}))

        # Generate and offer PDF report download
        st.markdown("---")
        col1, col2 = st.columns(2)

        with col1:
            # Generate PDF report
            pdf_file = generate_pdf_report(parsed, results)
            with open(pdf_file, "rb") as f:
                pdf_bytes = f.read()

            st.download_button(
                label="📥 Download PDF Report",
                data=pdf_bytes,
                file_name=f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                key="pdf_report",
                help="Download a detailed PDF report of the analysis"
            )

            # Clean up the temporary file
            os.unlink(pdf_file)

else:
    # Display welcome message and instructions when no file is uploaded
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("""
        ## Welcome to the Phishing Email Analyzer

        This tool helps you analyze email files (.eml) for potential phishing indicators using multiple heuristics:

        1. **Link Mismatches**: Detects when link text doesn't match the actual URL
        2. **Spoofed Headers**: Identifies inconsistencies in email headers
        3. **Suspicious Domains**: Finds lookalike domains that may be impersonating legitimate ones

        Upload an email file using the uploader above to get started.
        """)
    with col2:
        st.image("https://img.icons8.com/fluency/240/000000/phishing.png", width=200)