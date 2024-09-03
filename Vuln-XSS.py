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
    "Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
    "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.1.17 (KHTML, like Gecko) Version/7.1 Safari/537.85.10",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36 LBBROWSER",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.134 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.94 Safari/537.36",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36 OPR/31.0.1889.174",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:40.0) Gecko/20100101 Firefox/40.0.2 Waterfox/40.0.2",
    "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) CriOS/43.0.2357.61 Mobile/12F69 Safari/600.1.4",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.124 Safari/537.36"
]


def print_banner():
    banner=f"""{Style.BRIGHT}{Fore.RED}

 ____   ____        __                ____  ____   ______    ______   
|_  _| |_  _|      [  |              |_  _||_  _|.' ____ \ .' ____ \  
  \ \   / /__   _   | |  _ .--.  ______\ \  / /  | (___ \_|| (___ \_| 
   \ \ / /[  | | |  | | [ `.-. ||______|> `' <    _.____`.  _.____`.  
    \ ' /  | \_/ |, | |  | | | |      _/ /'`\ \_ | \____) || \____) | 
     \_/   '.__.'_/[___][___||__]    |____||____| \______.' \______.' 
                                                                      V1.0       

                                                                      
USE IT ONLY IN LEGAL TARGETS OR WHERE YOU HAVE OBTAINED EXPLICIT PERMISSION.                                                                                                          
"""
    print(banner)


def signal_handler(sig, frame):
    print(f"{Fore.RED}{Style.BRIGHT}\nInterrupted! Stopping threads...")
    try:
        stop_event.set()
        sys.exit(0)
    except:
        pass


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
    def __init__(self, url, request_file, payload_file, threads_count, wait_time, random_agent, show_browser, cookies):
        self.url = url
        self.request_file = request_file
        self.payload_file = payload_file
        self.threads_count = threads_count
        self.wait_time = wait_time
        self.random_agent = random_agent
        self.show_browser = show_browser
        self.found_payloads = 0
        self.tested_payloads_count = 0
        self.total_payloads = 0
        self.lock = threading.Lock()
        self.drivers = []
        self.progress_thread = None
        self.body_template = ''
        self.headers = {}
        self.input_names = []
        self.action_url = None  # Add this line for action URL
        self.fuzz_names = []
        self.driver_path = None
        self.lock_alert = 0
        self.cookies = cookies
    
    def driver_restart(self):
        chrome_options = Options()
        if self.show_browser:
            pass
        else:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--disable-logging")
        chrome_options.page_load_strategy = 'eager'
        service = Service(executable_path=self.driver_path)

        if self.random_agent:
            user_agent = random.choice(user_agents)
            print(f"{Fore.YELLOW}User-agent: {user_agent}")
            chrome_options.add_argument(f"user-agent={user_agent}")
        
        # Create a new WebDriver instance
        driver = webdriver.Chrome(service=service, options=chrome_options, service_log_path='NUL')
        
        # Open the URL to be able to add cookies
        driver.get(self.url)
        
        # Add cookies to the driver
        if self.cookies:
            for name, value in self.cookies.items():
            # Only add cookie if it does not already exist
                existing_cookies = driver.get_cookies()
                if not any(cookie['name'] == name for cookie in existing_cookies):
                    driver.add_cookie({'name': name, 'value': value})
        
        self.lock_alert += 1
        driver.set_page_load_timeout(25)
        time.sleep(1)
        return driver


    def initialize_drivers(self):
        chrome_options = Options()
        if self.show_browser:
            pass
        else:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--disable-logging")
        chrome_options.page_load_strategy = 'eager'

        for i in range(self.threads_count):
            if self.random_agent:
                user_agent = random.choice(user_agents)
                chrome_options.add_argument(f"user-agent={user_agent}")
            service = Service(executable_path=self.driver_path)
            driver = webdriver.Chrome(service=service, options=chrome_options, service_log_path='NUL')
            driver.get(self.url)  # Open the URL to add cookies to the domain

            if self.cookies:
                for name, value in self.cookies.items():
                    # Only add cookie if it does not already exist
                    existing_cookies = driver.get_cookies()
                    if not any(cookie['name'] == name for cookie in existing_cookies):
                        driver.add_cookie({'name': name, 'value': value})

            print(f"{Fore.YELLOW}{Style.BRIGHT}User-agent: {user_agent}")
            print(f"{Fore.GREEN}{Style.BRIGHT}Thread {i + 1} is ready")
            driver.set_page_load_timeout(25)
            self.drivers.append(driver)


    def cookie_finder(self):
        cookie_pairs = self.cookies.split('; ')
        self.cookies = {}
        for pair in cookie_pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                self.cookies[key] = value       


    def extract_data_from_request(self):
        with open(self.request_file, 'r') as file:
            lines = file.readlines()

        url = None
        self.cookies = {}
        self.form_data = {}  # Initialize form_data dictionary
        self.action_url = None  # Initialize action_url
        
        for line in lines:
            if line.startswith("Referer:"):
                url = line.split()[1]  # Extract URL from Referer header
            elif line.startswith("POST"):
                # Extract action URL from POST request line
                self.action_url = line.split()[1].strip()
            elif line.startswith("Cookie:"):
                # Extract cookies from Cookie header
                cookie_string = line[len("Cookie:"):].strip()
                cookie_pairs = cookie_string.split('; ')
                for pair in cookie_pairs:
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        self.cookies[key] = value
            elif ':' in line:
                continue  # Skip other headers
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
        print(f"Cookies: {self.cookies}")  # Print extracted cookies


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
                elif action =='':
                    target_form = form

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
            
            try: 
                submit_button = driver.find_element(By.CSS_SELECTOR, "input[type='submit']")
                submit_button.click()
            except:
                driver.execute_script("arguments[0].submit();", target_form)        
        
        except Exception as e:
            print(f"{Fore.RED}Unexpected error when fill the form: {e}")


    def test_post_request(self, payloads, driver):
        for payload in payloads:
            if driver.service.is_connectable():
                pass
            else:
                sys.exit(0)
            
            try:
                driver.get(self.url)
                try:
                    self.fill_form_and_submit(payload, driver)
                    WebDriverWait(driver, self.wait_time).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    print(f"{Fore.GREEN}{Style.BRIGHT}XSS found! Payload: {payload.strip()}")

                    with self.lock:
                        self.found_payloads += 1

                        with open(self.log_filename, 'a', encoding='utf-8') as log_file:
                            log_file.write(f"{payload.strip()}\n")

                    i = 0
                    while True:
                        if i == 7:
                            print(f"{Fore.YELLOW}{Style.BRIGHT}Driver stuck, restarting driver.")
                            driver.quit()
                            driver = self.driver_restart()
                            break
                        else:
                            try:
                                alert.accept()
                                i = i + 1
                            except NoAlertPresentException:
                                break   

                except UnexpectedAlertPresentException as a:
                    print(f"{Fore.RED} {type(a).__name__}: {str(a)}")

                    
                with self.lock:
                    self.tested_payloads_count += 1
                        
            except Exception :
                with self.lock:
                    self.tested_payloads_count += 1
                print(f"{Fore.RED}XSS not found: {payload.strip()}")

        driver.quit()



    def test_get_request(self, payloads, driver):
        for payload in payloads:
            if driver.service.is_connectable():
                pass
            else:
                break

            try:
                test_url = self.url.replace('FUZZ', payload.strip())
                driver.get(test_url)
    
                try:
                    # Wait for the alert to appear
                    WebDriverWait(driver, self.wait_time).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    print(f"{Fore.GREEN}{Style.BRIGHT}XSS found! Payload: {payload.strip()}")
                    
                    with self.lock:
                        self.found_payloads += 1
                        
                        # Write found payload to log file immediately
                        with open(self.log_filename, 'a', encoding='utf-8') as log_file:
                            log_file.write(f"{test_url}\n")
                    
                    i = 0
                    while True:
                        if i == 7:
                            print(f"{Fore.YELLOW}{Style.BRIGHT}Driver stuck, restarting driver.")
                            driver.quit()
                            driver = self.driver_restart()
                            break
                        else:
                            try:
                                alert.accept()
                                i = i + 1
                            except NoAlertPresentException:
                                break  

                except UnexpectedAlertPresentException as a:
                    print(f"{Fore.RED} {type(a).__name__}: {str(a)}")

                    
                with self.lock:
                    self.tested_payloads_count += 1
                        

            except Exception :
                with self.lock:
                    self.tested_payloads_count += 1
                print(f"{Fore.RED}XSS not found: {payload.strip()}")

        driver.quit()
            

    def choose_request_methode(self):
                
        if self.request_file:
            self.extract_data_from_request()
            return "post"
                    
        elif self.url:
            if self.cookies:
                self.cookie_finder()
            return "get"  

    def print_test_duration(self, start_time, end_time):
        test_duration = end_time - start_time
        minutes, seconds = divmod(int(test_duration), 60)
        print(f"{Fore.LIGHTMAGENTA_EX}{Style.BRIGHT}Total payload test duration: {minutes}m {seconds}s")


    def log_file(self):
        if not os.path.exists('logs'):
            os.makedirs('logs')

        site_name = urlparse(self.url).netloc
        current_time = time.strftime("%Y-%m-%d__%H-%M")
        
        self.log_filename = f"logs/{site_name}_{current_time}.log"


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
        
        method = self.choose_request_methode()
        self.log_file()

        self.initialize_drivers()
        start_time = time.time()

        self.progress_thread = threading.Thread(target=self.print_progress)
        self.progress_thread.start()

        if self.threads_count > 1:
            threads = []
            try:
                chunk_size = len(payloads) // self.threads_count 
                for i in range(self.threads_count):
                    start_index = i * chunk_size
                    if i == self.threads_count - 1:
                        end_index = len(payloads)
                    else:
                        end_index = (i + 1) * chunk_size
                    thread_payloads = payloads[start_index:end_index] 
                    if method=="post":
                        thread = threading.Thread(target=self.test_post_request, args=(thread_payloads, self.drivers[i]))
                    elif method == "get":
                        thread = threading.Thread(target=self.test_get_request, args=(thread_payloads, self.drivers[i]))
                    threads.append(thread)
                    thread.start()        
            except:
                pass

            for thread in threads:
                thread.join()
            
        else:
            if method=="post":
                self.test_post_request(payloads, self.drivers[0])
            elif method == "get":
                self.test_get_request(payloads, self.drivers[0])

        stop_event.set()
        self.progress_thread.join
        end_time = time.time()

        if self.found_payloads:
            print(f"{Fore.CYAN}{Style.BRIGHT}\n\nXSS Payloads found:{self.found_payloads}\n")
            print(f"{Fore.CYAN}{Style.BRIGHT}All correct payloads have been saved to the ./{self.log_filename} file.")
        else:
            print(f"{Fore.YELLOW}{Style.BRIGHT}XSS not found.")
        self.print_test_duration(start_time, end_time)
        print(f"{Fore.CYAN}{Style.BRIGHT}Total alert lock: {self.lock_alert}")

        sys.exit(1)

    def print_progress(self):
        while not stop_event.is_set():
            with self.lock:
                print(f"{Fore.BLUE}{Style.BRIGHT}Tested payloads: {self.tested_payloads_count}/{self.total_payloads} ({round(self.tested_payloads_count / self.total_payloads * 100, 1)}%)")
            time.sleep(20)
        


def print_custom_help():
    help_text = f"""{Fore.CYAN}{Style.BRIGHT}
XSS Checker - This tool scans a URL or request file for XSS vulnerabilities.

optional arguments:
  -h, --help         show this help message and exit
  --url URL          Target URL (must contain FUZZ placeholder) or file containing URLs
  --request REQUEST  Request file (HTTP request template)
  --payload PAYLOAD  File containing payloads
  --threads THREADS  Number of threads
  --wait WAIT        Wait time for alerts to appear
  --random-agent     Use random user-agent
  --show-browser     Shows open browsers
  --cookies          Add cookies
  
Example usage:
  python Vuln-XSS.py --url url.txt --threads 15 --payload './payloads/best_payload(1500).txt'
  python Vuln-XSS.py --request request.txt --threads 15 --payload './payloads/best_payload(1500).txt' --random-agent
"""
    print(help_text)

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="XSS Checker - This tool scans a URL or request file for XSS vulnerabilities.",
        usage=f"{Fore.YELLOW}{Style.BRIGHT}python xss-scanner.py [-h] [--url 'url' or url.txt] [--request request.txt] --payload payload.txt [--threads THREADS] [--wait WAIT] [--random-agent] [--show-browser]"
    )
    parser.add_argument("--url", help="Target URL (must contain FUZZ placeholder) or file containing URLs")
    parser.add_argument("--request", help="Request file (HTTP request template)")
    parser.add_argument("--payload", required=True, help="File containing payloads")
    parser.add_argument("--threads", type=int, default=1, help="Number of threads")
    parser.add_argument("--wait", type=int, default=2, help="Wait time for alerts to appear")
    parser.add_argument("--random-agent", action='store_true', help="Use random user-agent")
    parser.add_argument("--show-browser", action='store_true', help="show opening browsers")
    parser.add_argument("--cookies", help="Add cookies")

    if '--help' in sys.argv or '-h' in sys.argv:
        print_custom_help()
        sys.exit(0)

    args = parser.parse_args()

    urls = []

    if not args.url and not args.request:
        print(f"{Fore.RED}\nError: Either --url or --request must be provided.")
        sys.exit(1)

    if args.url and args.request:
        print(f"{Fore.RED}\nError: You cannot provide both --url and --request.")
        sys.exit(1)

    if args.url:
        if os.path.isfile(args.url):
            with open(args.url, 'r', encoding='utf-8') as url_file:
                urls = []
                for line in url_file:
                    stripped_line = line.strip()
                    if stripped_line and not stripped_line.startswith('#'):
                        urls.append(stripped_line)
        else:
            urls = [args.url]

        for url in urls:
            if "FUZZ" not in url:
                print(f"{Fore.RED}\nError: The URL '{url}' must contain the 'FUZZ' placeholder.")
                continue
            print(f"{Fore.GREEN}{Style.BRIGHT}\nTesting url is {url}")
            scanner = XSSScanner(url, args.request, args.payload, args.threads, args.wait, args.random_agent, args.show_browser, args.cookies)
            scanner.start_scanning()

    elif args.request:
        if not os.path.exists(args.request):
            print(f"{Fore.RED}\nError: Request file does not exist.")
            sys.exit(1)

        with open(args.request, 'r', encoding='utf-8') as file:
            request_content = file.read()
            if "FUZZ" not in request_content:
                print(f"{Fore.RED}\nError: The request file must contain the 'FUZZ' placeholder.")
                sys.exit(1)

        scanner = XSSScanner(None, args.request, args.payload, args.threads, args.wait, args.random_agent, args.show_browser, None)
        scanner.start_scanning()

    if not os.path.exists(args.payload):
        print(f"{Fore.RED}\nError: Payload file does not exist.")
        sys.exit(1)

if __name__ == "__main__":     
    signal.signal(signal.SIGINT, signal_handler)
    main()

