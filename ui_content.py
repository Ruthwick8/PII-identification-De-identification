# ui_content.py

# --- Main Window & Header ---
WINDOW_TITLE = "PII Detection & De-Identification Tool"
HEADER_TITLE = "PII Detection & De-Identification Tool"
HEADER_SUBTITLE = "Scan files, configure masking, and generate advanced accuracy reports."

# --- Buttons ---
SELECT_FILE_BTN = "Select Input File"
RUN_BTN = "Run Detection"
NEXT_BTN = "Next: Configure De-Identification →"
BACK_BTN = "← Back to Regex"
SAVE_DEIDENTIFIED_BTN = "Save De-Identified File"
SAVE_SUMMARY_BTN = "Save Summary Report"

# --- Labels & Titles ---
NO_FILE_SELECTED_LBL = "No file selected."
REGEX_GROUP_TITLE = "Step 1: Regex Pattern Configuration"
DEID_GROUP_TITLE = "Step 2: De-Identification & Validation"
PII_TYPE_HEADER = "<b>PII Type</b>"
MASK_HEADER = "<b>Mask?</b>"
STRATEGY_HEADER = "<b>Strategy</b>"
CHAR_HEADER = "<b>Char</b>"
EXPECTED_HEADER = "<b>Expected #</b>"

# --- Radio Buttons & Tabs ---
PRESET_RADIO = "Use Preset"
CUSTOM_RADIO = "Use Custom"
SUMMARY_TAB = "Summary Report"
PREVIEW_TAB = "De-identified Data Preview"

# --- Masking Strategies ---
MASKING_STRATEGIES = ["Partial Mask (Default)", "Full Mask", "Hash (SHA256)", "Encryption", "Redact"]

# --- Messages & Dialogs ---
FILE_FILTER = "All Supported Files (*.csv *.txt *.pdf);;CSV Files (*.csv);;Text Files (*.txt);;PDF Files (*.pdf)"
SELECT_FILE_DIALOG_TITLE = "Select Input File"
MISSING_LIB_TITLE = "Missing Library"
MISSING_LIB_MSG = "PyMuPDF is not installed. Please run 'pip install PyMuPDF' to process PDF files."
NO_FILE_WARNING_TITLE = "No File"
NO_FILE_WARNING_MSG = "Please select an input file first."
REGEX_ERROR_TITLE = "Regex Error"
REGEX_ERROR_MSG = "Invalid {pii_label} regex: {error}. It will be ignored."
COMPLETED_INFO_TITLE = "Completed"
COMPLETED_INFO_MSG = "Detection and de-identification finished."
NO_DATA_SAVE_TITLE = "No Data"
NO_DEID_DATA_MSG = "No de-identified data to save."
NO_SUMMARY_DATA_MSG = "No summary to save."
SAVE_CSV_DIALOG_TITLE = "Save De-Identified CSV"
SAVE_TXT_DIALOG_TITLE = "Save De-Identified Text File"
SAVE_SUMMARY_DIALOG_TITLE = "Save Summary Report"
SAVE_SUCCESS_MSG = "Data saved to {path}"
SAVE_FAILURE_MSG = "Failed to save file: {error}"
CONFIRM_EXIT_TITLE = 'Confirm Exit'
CONFIRM_EXIT_MSG = 'A scan is in progress. Are you sure you want to exit?'

# --- Summary Report Text ---
def get_summary_report(summary, report_metrics, pii_labels):
    report = [
        "--- Detection Summary Report ---\n",
        f"Rows Processed: {summary.get('rows_processed', 0)}\n"
    ]
    header = f"{'PII Category':<20} | {'Found':<7} | {'Expected':<10} | {'TP':<5} | {'FP':<5} | {'Precision':<10} | {'Recall':<8} | {'F1-Score':<10} | {'Risk Level'}"
    report.append(header)
    report.append("-" * len(header))

    for key, metrics in report_metrics.items():
        expected_str = str(metrics['expected']) if metrics['expected'] is not None else 'N/A'
        line = (f"{pii_labels.get(key, key.title()):<20} | {metrics['found']:<7} | {expected_str:<10} | "
                f"{metrics['tp']:<5} | {metrics['fp']:<5} | {metrics['precision']:<10.2f} | {metrics['recall']:<8.2f} | "
                f"{metrics['f1']:<10.2f} | {metrics['risk']}")
        report.append(line)

    report.extend([
        "\n" + "="*40,
        "\n--- Accuracy Formulas ---\n",
        "Precision = TP / (TP + FP)  (Ability to avoid false positives)",
        "Recall    = TP / (TP + FN)     (Ability to find all positives)",
        "F1-Score  = 2 * (Precision * Recall) / (Precision + Recall)\n",
        "\n--- Risk Matrix ---\n",
        "Low:      All found items were expected (Precision = 1.0)",
        "Medium:   High precision (>= 0.8), few false positives.",
        "High:     Moderate precision (>= 0.5), some false positives.",
        "Critical: Low precision (< 0.5) or found items when none expected."
    ])
    return "\n".join(report)