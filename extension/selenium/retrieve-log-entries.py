#!/usr/bin/env python3

import argparse
import os
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Get variable from python script",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--geckodriver", "-g", default="/home/cyrill/Downloads/geckodriver", help="geckodriver executable")
    parser.add_argument("--extension-xpi", "-e", default="/home/cyrill/github/fpki-firefox-extension/extension.xpi", help="compressed extension (.xpi file)")

    return parser.parse_args()


def main():
    args = parse_arguments()

    executable_path = args.geckodriver
    driver = webdriver.Firefox(executable_path=executable_path)
    path = os.path.abspath(args.extension_xpi)
    driver.install_addon(path, temporary=True)
    driver.get("http://stackoverflow.com")
    driver.execute_script("""
window.extensionlogs = [];
document.addEventListener(
    "pageloadfinished",
    function(e){
        const ep = JSON.parse(e.detail);
        window.extensionContextLogEntries = ep;
    }, false);
""")

    while True:
        # retrieve the log entries and reset the variable
        log = driver.execute_script("""
const tmp = window.extensionContextLogEntries;
window.extensionContextLogEntries = null;
return tmp;
""")
        if log is not None:
            print('Got extension event: {}'.format(log))
        print("Waiting for new log...")
        time.sleep(0.3)

    # sleep to make sure that we have enough time to receive the custom event
    time.sleep(1000)
    driver.quit()


if __name__ == '__main__':
    main()
