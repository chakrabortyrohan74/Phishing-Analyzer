# Phishing Email Analyzer

A powerful tool for analyzing email files (.eml) to detect phishing attempts using multiple heuristics and machine learning techniques.

![Phishing Analyzer](https://img.icons8.com/fluency/240/000000/phishing.png)

## Features

- **Comprehensive Phishing Detection**: Analyzes emails using multiple heuristics:
  - Link mismatch detection (displayed text vs. actual URL)
  - Spoofed header identification
  - Lookalike domain detection
  - Risk score calculation

- **User-Friendly Interface**:
  - Clear visual indicators of risk level
  - Detailed explanations of findings
  - Interactive elements for exploring results
  - Educational content about phishing techniques

- **Detailed Reporting**:
  - Professional PDF reports
  - Text-based reports
  - Visual risk assessment
  - Actionable security recommendations

## Installation

### Prerequisites

- Python 3.7+
- pip (Python package manager)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/phishing-analyzer.git
   cd phishing-analyzer
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running the Application

Start the Streamlit web application:

```bash
streamlit run app.py
```

This will launch the application in your default web browser.

### Analyzing Emails

1. Upload an email file (.eml format) using the file uploader
2. View the analysis results in the Overview tab
3. Explore detailed findings in the Detailed Analysis tab
4. Review the email content and raw headers in their respective tabs
5. Download a PDF or text report for documentation

## How It Works

The analyzer uses several techniques to identify potential phishing attempts:

1. **Link Analysis**: Compares the displayed text of links with their actual destination URLs to detect deception.

2. **Header Analysis**: Examines email headers for inconsistencies, such as mismatches between the From, Reply-To, and Return-Path fields.

3. **Domain Analysis**: Uses Levenshtein distance to identify domains that look similar to legitimate ones (e.g., "amaz0n-payments.net" vs. "amazon.com").

4. **Risk Scoring**: Calculates an overall risk score based on the findings from the above analyses.

## Project Structure

- `app.py`: Main Streamlit application
- `heuristics.py`: Core analysis logic and phishing detection algorithms
- `email_parser.py`: Functions for parsing email files
- `uploads/`: Directory for storing uploaded email files
- `static/`: Static assets for the application
- `templates/`: HTML templates for reports

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Icons by [Icons8](https://icons8.com)
- Built with [Streamlit](https://streamlit.io/)
- PDF generation using [ReportLab](https://www.reportlab.com/)
