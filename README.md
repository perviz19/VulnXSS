# Vuln-XSS
Vuln-XSS is a tool designed for identifying Cross-Site Scripting (XSS) vulnerabilities in web applications. It helps to automate the testing process by using a variety of XSS payloads to detect potential security issues.

## Features
Test for XSS vulnerabilities using a range of payloads.
Support for different browser profiles and user-agents.
Ability to run tests in headless mode for efficiency.

## Installation
To get started, clone the repository using Git:
```bash
git clone https://github.com/perviz19/VulnXSS.git
```
## Install Dependencies
Navigate to the project directory and install the required Python packages:

```bash
pip install -r requirements.txt
```

## Usage
Run the tool with the following command to see the available options:

```bash
python Vuln-XSS.py -h
```

## Example
To run a basic scan, use:
```bash
python Vuln-XSS.py --url http://example.com --payload payloads/best_payload(1500).txt
```
Replace http://example.com with the URL of the web application you want to test.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue if you have suggestions or improvements.

## License
This project is licensed under the MIT License - see the [LICENSE] file for details.

## Contact
For any questions or support, please contact perviz.muslumov10@gmail.com.
