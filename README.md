# PyAnt
PyAnt: A Python-based web link scanner to detect potential phishing and other security threats through URL and content analysis.
# PyAnt: Python-Based Web Link Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Stars](https://img.shields.io/github/stars/pardiansyahputra/PyAnt.svg?style=social)](https://github.com/pardiansyahputra/PyAnt)

**PyAnt** is a Python-based application designed to help you scan web links for potential security threats such as phishing and other malicious links. It employs various analysis techniques, including blacklist checking, URL analysis (length, keywords, typosquatting, suspicious paths), and web content analysis (phishing keywords, form analysis), as well as following HTTP redirects to detect hidden threats.

## Key Features

* **Web Link Scanning:** Allows users to input a URL and scan all links found on that page.
* **Blacklist Checking:** Compares links against a known blacklist of malicious sites.
* **URL Analysis:** Analyzes the structure of URLs to identify suspicious patterns such as unusual length, dangerous keywords, and potential typosquatting.
* **Phishing Detection:** Analyzes web page content for phishing keywords and suspicious forms that submit sensitive data to different domains.
* **HTTP Redirect Following:** Capable of following HTTP redirects to analyze the final destination URL.
* **Direct IP Address Handling:** Can analyze links that are direct IP addresses by bypassing domain-based analysis.
* **Graphical User Interface (GUI):** Provides an easy-to-use graphical interface based on Tkinter.
* **Activity Logging:** Records all scanning and detection activities into an `app.log` file.
* **Visual Indicators:** Displays real-time scanning status and a summary of results at the end of the scan.

## Installation Guide

Here are the steps to install and run PyAnt:

1.  **Prerequisites:**
    * **Python 3.x:** Ensure you have Python 3.x installed on your system. You can download it from [https://www.python.org/downloads/](https://www.python.org/downloads/).
    * **pip:** The *Package installer for Python* is usually installed by default with Python.

2.  **Download Repository:**
    * Clone the PyAntiVirus repository from your GitHub:
        ```bash
        git clone [https://github.com/pardiansyahputra/PyAnt.git](https://github.com/pardiansyahputra/PyAnt.git)
        cd PyAnt
        ```

3.  **Install Dependencies:**
    * This application has several external dependencies that need to be installed. You can install them using pip:
        ```bash
        pip install -r requirements.txt
        ```
        Ensure you have created a `requirements.txt` file in the root directory of your project with the following content:
        ```
        requests
        beautifulsoup4
        tkinter
        ```

4.  **Run Application:**
    * Once all dependencies are installed, you can run the application with the command:
        ```bash
        python gui/main_window.py
        ```
        This will open the main window of the PyAnt application.

## Usage Instructions

1.  **Enter URL:** In the main application window, enter the URL you want to scan into the provided text box.
2.  **Click Scan Button:** Click the "Scan" button to start the scanning process.
3.  **View Results:** The scan results will be displayed in the text area below the button. Each link found will be analyzed, and its status (Safe, Suspicious, Potential Phishing) along with the reasons will be shown.
4.  **Scan Summary:** At the top of the results, you will see a summary of the total links scanned, the number of suspicious links, and the number of potential phishing links.
5.  **Cancel Scan:** If the scanning process takes too long or you want to stop it, you can click the "Cancel" button.
6.  **Activity Log:** Complete details of the scanning and detection process can be found in the `app.log` file, which will be created in the root directory of your project.

## Contribution Guidelines

If you are interested in contributing to the PyAnt project, you can do the following:

* Report any bugs or issues you find.
* Suggest new features or improvements.
* Submit pull requests with fixes or features you have implemented.

Please create a new issue for discussions or submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more information.

## Contact

You can contact me through the GitHub repository page.

---

**Thank you for using PyAnt!**
