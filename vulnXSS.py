import os
import argparse
import threading
import time
import signal
import sys
import random
import re
import winreg as reg
from selenium.webdriver.common.by import By
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
from colorama import Fore, init, Style

# Initialize colorama
init(autoreset=True)

# Global flag to stop threads
stop_event = threading.Event()

# List of user agents for random selection
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
]

def sanitize_filename(url):
    return re.sub(r'[<>:"/\\|?*\x00-\x1F]', '_', url)

def get_site_name(self):
    if self.url:
        return self.url

    if self.post_url:
        return self.post_url

    if self.request_file:
        with open(self.request_file, 'r', encoding='utf-8') as file:
            request_lines = file.readlines()
            
            for line in request_lines:
                if line.startswith("Referer:"):
                    self.post_url = line.split("Referer:")[1].strip()
                    return self.post_url

            raise ValueError("The request file must contain 'Referer'.")



def get_installed_chrome_version():
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Google\Chrome\BLBeacon")
        version, _ = reg.QueryValueEx(key, "version")
        return version
    except FileNotFoundError:
        try:
            key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"Software\Google\Chrome\BLBeacon")
            version, _ = reg.QueryValueEx(key, "version")
            return version
        except FileNotFoundError:
            try:
                key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Google\Chrome\BLBeacon")
                version, _ = reg.QueryValueEx(key, "version")
                return version
            except FileNotFoundError:
                raise Exception("Chrome is not installed or does not detect my version.")

def get_chromedriver_path():
    base_path = os.path.join(os.getenv("USERPROFILE"), '.wdm', 'drivers', 'chromedriver', 'win64')
    
    if os.path.exists(base_path):
        versions = os.listdir(base_path)
        
        if versions:
            # Sort versions by numeric values
            versions = sorted(versions, key=lambda x: list(map(int, x.split('.'))), reverse=True)
            latest_version = versions[0]
            
            chromedriver_version_path = os.path.join(base_path, latest_version)
            chromedriver_win32_path = os.path.join(chromedriver_version_path, 'chromedriver-win32', 'chromedriver.exe')
            
            if os.path.exists(chromedriver_win32_path):
                return chromedriver_win32_path
            else:
                return None
        else:
            return None
    else:
        return None
    


def get_chromedriver_version(driver_path):
    try:
        result = os.popen(f'"{driver_path}" --version').read()
        return result.split()[1]
    except Exception as e:
        return None



class XSSScanner:
    def __init__(self, url, request_file, payload_file, threads_count, wait_time, random_agent):
        self.url = url
        self.request_file = request_file
        self.payload_file = payload_file
        self.threads_count = threads_count
        self.wait_time = wait_time
        self.random_agent = random_agent
        self.found_payloads = []
        self.tested_payloads_count = 0
        self.total_payloads = 0
        self.lock = threading.Lock()
        self.drivers = []
        self.progress_thread = None
        self.body_template = ''
        self.headers = {}
        self.input_names = []
        self.post_url = None
        self.action_url = None  # Add this line for action URL
        self.fuzz_names = []
        self.driver_path = None


        if not os.path.exists('logs'):
            os.makedirs('logs')

        site_name = urlparse(get_site_name(self)).netloc
        current_time = time.strftime("%Y-%m-%d__%H-%M")
        

        self.log_filename = f"logs/{site_name}_{current_time}.txt"

        if self.request_file:
            self.extract_data_from_request()

    def initialize_drivers(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--log-level=3")
        if self.random_agent:
            user_agent = random.choice(user_agents)
            print(f"{Fore.YELLOW}User-agent: {user_agent}")
            chrome_options.add_argument(f"user-agent={user_agent}")

        for i in range(self.threads_count):
            driver = webdriver.Chrome(service=Service(executable_path=self.driver_path) ,options=chrome_options)
            print(f"{Fore.GREEN}Thread {i + 1} is ready")
            self.drivers.append(driver)
            time.sleep(2)

    def extract_data_from_request(self):
        with open(self.request_file, 'r') as file:
            lines = file.readlines()

        url = None
        self.form_data = {}  # Initialize form_data dictionary
        self.action_url = None  # Initialize action_url
        
        for line in lines:
            if line.startswith("Referer:"):
                url = line.split()[1]  # Extract URL from Referer header
            elif line.startswith("POST"):
                # Extract action URL from POST request line
                self.action_url = line.split()[1].strip()
            elif ':' in line:
                continue  # Skip headers
            elif '=' in line:
                key_value_pairs = line.strip().split('&')
                for pair in key_value_pairs:
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        self.form_data[key] = value
                        if value == 'FUZZ':
                            self.fuzz_names.append(key)  # Add name to fuzz_names list

        self.url = url  # Set the URL extracted from request file
        print(f"{Fore.YELLOW}\nForm Data: {self.form_data}")
        print(f"FUZZ names: {self.fuzz_names}")


    def fill_form_and_submit(self, payload, driver):
        try:
            # Wait for the form to be present on the page
            WebDriverWait(driver, self.wait_time).until(EC.presence_of_element_located((By.TAG_NAME, 'form')))
            # Find all forms on the page
            forms = driver.find_elements(By.TAG_NAME, 'form')

            # Iterate through forms to find the one with the matching action URL
            target_form = None
            for form in forms:
                action = form.get_attribute('action')
                if self.action_url in action:
                    target_form = form
                    break
            
            if target_form is None:
                print(f"{Fore.RED}No form found with action URL: {self.action_url}")
                return

            # Fill input fields with the provided payload
            input_elements = target_form.find_elements(By.TAG_NAME, 'input')
            for input_element in input_elements:
                input_name = input_element.get_attribute('name')
                if input_name in self.fuzz_names:
                    driver.execute_script("arguments[0].value = arguments[1];", input_element, payload)
                elif input_name in self.form_data:
                    value = self.form_data[input_name]
                    driver.execute_script("arguments[0].value = arguments[1];", input_element, value)

            # Fill textarea fields
            textarea_elements = target_form.find_elements(By.TAG_NAME, 'textarea')
            for textarea_element in textarea_elements:
                input_name = textarea_element.get_attribute('name')
                if input_name in self.fuzz_names:
                    driver.execute_script("arguments[0].value = arguments[1];", textarea_element, payload)
                elif input_name in self.form_data:
                    value = self.form_data[input_name]
                    driver.execute_script("arguments[0].value = arguments[1];", textarea_element, value)
            
            driver.execute_script("arguments[0].submit();", target_form)        
        
        except Exception as e:
            print(f"{Fore.RED}Unexpected error: {e}")



    def test_get_request(self, payloads, driver):
        for payload in payloads:
            if stop_event.is_set():
                sys.exit(0)
            
            try:
                test_url = self.url.replace('FUZZ', payload.strip())
                driver.get(test_url)
                
                try:
                    # Wait for the alert to appear
                    WebDriverWait(driver, self.wait_time).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    print(f"{Fore.GREEN}{Style.BRIGHT}XSS found! Payload: {payload.strip()}")
                    
                    with self.lock:
                        self.found_payloads.append(payload.strip())
                        
                        # Write found payload to log file immediately
                        with open(self.log_filename, 'a', encoding='utf-8') as log_file:
                            log_file.write(f"{test_url}\n")

                    while True:
                        try:
                            WebDriverWait(driver, 1).until(EC.alert_is_present())
                            alert.accept()
                        except NoAlertPresentException:
                            break  

                except UnexpectedAlertPresentException:
                    pass

                
                with self.lock:
                    self.tested_payloads_count += 1
                    

            except Exception as e:
                with self.lock:
                    self.tested_payloads_count += 1
                print(f"{Fore.RED}XSS not found: {payload.strip()}")


    def test_post_request(self, payloads, driver):
        for payload in payloads:
            if stop_event.is_set():
                sys.exit(0)
            
            try:
                driver.get(self.post_url)
                try:
                    self.fill_form_and_submit(payload, driver)
                    WebDriverWait(driver, self.wait_time).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    print(f"{Fore.GREEN}{Style.BRIGHT}XSS found! Payload: {payload.strip()}")

                    with self.lock:
                        self.found_payloads.append(payload.strip())
                        with open(self.log_filename, 'a', encoding='utf-8') as log_file:
                            log_file.write(f"{payload.strip()}\n")

                    while True:
                        try:
                            WebDriverWait(driver, 1).until(EC.alert_is_present())
                            alert.accept()
                        except NoAlertPresentException:
                            break  

                except UnexpectedAlertPresentException:
                    pass
            
                with self.lock:
                        self.tested_payloads_count += 1
                    
            except Exception as e:
                with self.lock:
                    self.tested_payloads_count += 1
                print(f"{Fore.RED}XSS not found: {payload.strip()}")
            

    def choose_request_methode(self, payloads, driver):
        
        if self.post_url:
            self.test_post_request(payloads, driver)
                    
        elif self.url:
            self.test_get_request(payloads, driver)   

    def print_test_duration(self, start_time, end_time):
        test_duration = end_time - start_time
        minutes, seconds = divmod(int(test_duration), 60)
        print(f"{Fore.LIGHTMAGENTA_EX}{Style.BRIGHT}Total payload test duration: {minutes}m {seconds}s")


    def start_scanning(self):
        with open(self.payload_file, 'r', encoding='utf-8') as file:
            payloads = file.readlines()
            self.total_payloads = len(payloads)


        chrome_version = get_installed_chrome_version()

        #Chrome and chrome driver version check
        while True: 
            if not self.driver_path:
                try:
                    self.driver_path = get_chromedriver_path()

                    if self.driver_path:
                        chromedriver_version = get_chromedriver_version(self.driver_path)
                        if chrome_version.startswith(chromedriver_version.split('.')[0]):
                            print(f"Suitable chromedriver found: {chromedriver_version}")
                        else:
                            webdriver.Chrome(service=Service(ChromeDriverManager().install()))
                    else:
                        webdriver.Chrome(service=Service(ChromeDriverManager().install()))
                except:
                    pass
            else:
                break

        self.initialize_drivers()

        start_time = time.time()

        if self.threads_count > 1:
            threads = []
            chunk_size = len(payloads) // self.threads_count  # Her thread için payload sayısı
            for i in range(self.threads_count):
                start_index = i * chunk_size
                if i == self.threads_count - 1:  # Son thread tüm kalan payloadları alır
                    end_index = len(payloads)
                else:
                    end_index = (i + 1) * chunk_size
                thread_payloads = payloads[start_index:end_index]  # Thread'e özel payload listesi
                thread = threading.Thread(target=self.choose_request_methode, args=(thread_payloads, self.drivers[i]))
                threads.append(thread)
                thread.start()
                

            self.progress_thread = threading.Thread(target=self.print_progress)
            self.progress_thread.start()

            for thread in threads:
                thread.join()

            stop_event.set()
            self.progress_thread.join()

        else:
            self.choose_request_methode(payloads, self.drivers[0])

        end_time = time.time()

        if self.found_payloads:
            print(f"{Fore.MAGENTA}{Style.BRIGHT}\n\nXSS Payloads found:{len(self.found_payloads)}\n")
            for payload in self.found_payloads:
                print(f"{Fore.GREEN}{Style.BRIGHT}{payload}")
            print(f"{Fore.MAGENTA}{Style.BRIGHT}All correct payloads have been saved to the ./logs directory.")
        else:
            print(f"{Fore.YELLOW}{Style.BRIGHT}XSS not found.")
        self.print_test_duration(start_time, end_time)


    def print_progress(self):
        while not stop_event.is_set():
            with self.lock:
                print(f"{Fore.BLUE}{Style.BRIGHT}Tested payloads: {self.tested_payloads_count}/{self.total_payloads} ({round(self.tested_payloads_count / self.total_payloads * 100, 1)}%)")
            time.sleep(15)


def signal_handler(sig, frame):
    print(f"{Fore.RED}{Style.BRIGHT}\nInterrupted! Stopping threads...")
    stop_event.set()
    sys.exit(0)


def print_custom_help():
    help_text = f"""{Fore.CYAN}{Style.BRIGHT}
XSS Checker - This tool scans a URL or request file for XSS vulnerabilities.

usage: python xss-scanner.py [-h] [--url 'url' or url.txt] [--request request.txt] --payload payload.txt [--threads THREADS] [--wait WAIT] [--random-agent]

optional arguments:
  -h, --help         show this help message and exit
  --url URL          Target URL (must contain FUZZ placeholder) or file containing URLs
  --request REQUEST  Request file (HTTP request template)
  --payload PAYLOAD  File containing payloads
  --threads THREADS  Number of threads
  --wait WAIT        Wait time for alerts to appear
  --random-agent     Use random user-agent

Example usage:
  python xss-scanner.py --url url.txt --payload payloads.txt --threads 15
  python xss-scanner.py --request request.txt --payload payloads.txt --threads 15
"""
    print(help_text)

def main():
    parser = argparse.ArgumentParser(
        description="XSS Checker - This tool scans a URL or request file for XSS vulnerabilities.",
        usage="python xss-scanner.py [-h] [--url 'url' or url.txt] [--request request.txt] --payload payload.txt [--threads THREADS] [--wait WAIT] [--random-agent]",
        add_help=False  # Disable the default help message
    )
    parser.add_argument("--url", help="Target URL (must contain FUZZ placeholder) or file containing URLs")
    parser.add_argument("--request", help="Request file (HTTP request template)")
    parser.add_argument("--payload", required=True, help="File containing payloads")
    parser.add_argument("--threads", type=int, default=1, help="Number of threads")
    parser.add_argument("--wait", type=int, default=2, help="Wait time for alerts to appear")
    parser.add_argument("--random-agent", action='store_true', help="Use random user-agent")

    if '--help' in sys.argv or '-h' in sys.argv:
        print_custom_help()
        sys.exit(0)

    args = parser.parse_args()

    urls = []

    if not args.url and not args.request:
        print(f"{Fore.RED}Error: Either --url or --request must be provided.")
        sys.exit(1)

    if args.url and args.request:
        print(f"{Fore.RED}Error: You cannot provide both --url and --request.")
        sys.exit(1)

    if args.url:
        if os.path.isfile(args.url):
            with open(args.url, 'r', encoding='utf-8') as url_file:
                urls = [line.strip() for line in url_file if line.strip()]
        else:
            urls = [args.url]

        for url in urls:
            if "FUZZ" not in url:
                print(f"{Fore.RED}Error: The URL '{url}' must contain the 'FUZZ' placeholder.")
                continue
            print(f"{Fore.GREEN}{Style.BRIGHT}\nTesting url is {url}")
            scanner = XSSScanner(url, args.request, args.payload, args.threads, args.wait, args.random_agent)
            scanner.start_scanning()

    elif args.request:
        if not os.path.exists(args.request):
            print(f"{Fore.RED}Error: Request file does not exist.")
            sys.exit(1)

        with open(args.request, 'r', encoding='utf-8') as file:
            request_content = file.read()
            if "FUZZ" not in request_content:
                print(f"{Fore.RED}Error: The request file must contain the 'FUZZ' placeholder.")
                sys.exit(1)

        scanner = XSSScanner(None, args.request, args.payload, args.threads, args.wait, args.random_agent)
        scanner.start_scanning()

    if not os.path.exists(args.payload):
        print(f"{Fore.RED}Error: Payload file does not exist.")
        sys.exit(1)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()

