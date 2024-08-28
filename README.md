# Vuln-XSS
Vuln-XSS is a tool designed for identifying Cross-Site Scripting (XSS) vulnerabilities in web applications. It helps to automate the testing process by using a variety of XSS payloads to detect potential security issues.

## Disclaimer
This software is provided "as is" and should only be used in compliance with applicable laws and regulations. The authors are not responsible for any misuse or legal consequences resulting from its use. Use it responsibly and at your own risk.


## Installation
To get started, clone the repository using Git:
```bash
git clone https://github.com/perviz19/VulnXSS.git
cd VulnXSS
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
python Vuln-XSS.py --url url.txt --threads 10 --payload payloads/best_payload(1500).txt 
```

## Contributing
Contributions are welcome! Please submit a pull request or open an issue if you have suggestions or improvements.

## License
This project is licensed under the GNU AFFERO GENERAL PUBLIC LICENSE v3.0 - see the [LICENSE](LICENSE) file for details.

## Contact
For any questions or support, please contact perviz.muslumov10@gmail.com.
