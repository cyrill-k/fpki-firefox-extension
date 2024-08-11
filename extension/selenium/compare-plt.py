#!/usr/bin/env python3

import argparse
import os
import time
import csv
from contextlib import closing, contextmanager
import itertools

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Get variable from python script",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument('positionalarg', metavar='N', type=str, nargs='*')
    parser.add_argument("--geckodriver", "-g", default="/home/cyrill/Downloads/geckodriver", help="geckodriver executable")
    parser.add_argument("--extension-xpi-js", default="/home/cyrill/github/fpki-firefox-extension/extension-js.xpi", help="compressed extension (.xpi file) without GO WASM optimizations")
    parser.add_argument("--extension-xpi-wasm", default="/home/cyrill/github/fpki-firefox-extension/extension-wasm.xpi", help="compressed extension (.xpi file) with GO WASM optimizations")
    parser.add_argument("--output-file", "-o", default="plt-measurements.csv", help="output csv file")
    parser.add_argument("--toplist-file", "-t", type=str, default="/home/cyrill/inf-gitlab/OU-PERRIG/cyrill/ct-log-scraping/input/top-1m.csv", help="Alexa most popular domain list csv file")
    parser.add_argument("--toplist-threshold", type=int, default=100000, help="highest Alexa rank to extract (inclusive)")
    parser.add_argument("--repetitions", "-r", type=int, default=1, help="number of times each webpage is fetched")

    return parser.parse_args()


def check_output_files(output_file_args, args):
    for arg_name in output_file_args:
        f = vars(args).get(arg_name)
        if os.path.exists(f):
            answer = input(f"Overwrite {f}? ")
            while True:
                if answer.lower() in ["y", "yes"]:
                    break
                elif answer.lower() in ["n", "no"]:
                    print(f"Output file {f} already exists, execution stopped")
                    exit(1)
                else:
                    answer = input("Please answer with y[es] or n[o]! ")


def run(domain, extension, args):
    try:
        executable_path = args.geckodriver

        options = FirefoxOptions()
        options.add_argument("--headless")
        driver = webdriver.Firefox(executable_path=executable_path, options=options)
        if extension is not None:
            path = os.path.abspath(extension)
            driver.install_addon(path, temporary=True)
        driver.get(f"https://{domain}")
        navigationStart = driver.execute_script("return window.performance.timing.navigationStart")
        responseStart = driver.execute_script("return window.performance.timing.responseStart")
        domComplete = driver.execute_script("return window.performance.timing.domComplete")
        loadEventEnd = driver.execute_script("return window.performance.timing.loadEventEnd")

        ''' Calculate the performance'''
        backendPerformance_calc = responseStart - navigationStart
        frontendPerformance_dom = domComplete - responseStart
        frontendPerformance_load = loadEventEnd - domComplete

        print(f"{domain} [extension={extension}]")
        print(f"Back End: {backendPerformance_calc}")
        print(f"Front End (dom): {frontendPerformance_dom}")
        print(f"Front End (load): {frontendPerformance_load}")

        driver.quit()

        return {"time-to-first-byte": backendPerformance_calc, "time-to-dom-completed": frontendPerformance_dom, "load-finished": frontendPerformance_load, "status": "success"}
    except Exception as e:
        print(e)
        return {"time-to-first-byte": 0, "time-to-dom-completed": 0, "load-finished": 0, "status": "failure"}


@contextmanager
def get_domains(args):
    if len(args.positionalarg) > 0:
        yield zip(range(1, len(args.positionalarg)+1), args.positionalarg)
    else:
        with open(args.toplist_file, newline='') as csvfile:
            csvreader = csv.reader(csvfile)
            rankedDomains = ((int(row[0]), row[1]) for row in csvreader)
            yield itertools.takewhile(lambda x: x[0] <= args.toplist_threshold, rankedDomains)


def main():
    args = parse_arguments()

    check_output_files(["output_file"], args)

    csvwriter = None
    with open(args.output_file, 'w', newline='') as measurementsCsvfile:
        for i in range(args.repetitions):
            with get_domains(args) as domains:
                for row in domains:
                    rank = int(row[0])
                    domain = row[1]
                    if rank <= args.toplist_threshold:
                        # run once to ensure that all DNS entries are cached (for a fairer comparison)
                        run(domain, None, args)
                        measurements = []
                        measurements.append({**{"rank": rank, "domain": domain, "use-extension": True, "parsing": "wasm"}, **run(domain, args.extension_xpi_wasm, args)})
                        measurements.append({**{"rank": rank, "domain": domain, "use-extension": True, "parsing": "js"}, **run(domain, args.extension_xpi_js, args)})
                        measurements.append({**{"rank": rank, "domain": domain, "use-extension": False, "parsing": None}, **run(domain, None, args)})
                        # print(".", end="", flush=True)
                        if csvwriter is None:
                            csvwriter = csv.DictWriter(measurementsCsvfile, fieldnames=measurements[0].keys())
                            csvwriter.writeheader()
                        csvwriter.writerows(measurements)

if __name__ == '__main__':
    main()
