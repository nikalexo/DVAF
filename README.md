# DVAF

The Debian Vulnerability Analysis Framework offers tools to gather and analyze vulnerability data about packages of the Debian GNU/Linux distribution. The scripts work on Debian GNU/Linux with python 3.7 (but should generally work on any Linux set-up). Some effort will be required by Windows users. A complete documentation of the framework is in the works... Somewhat experienced programmers will probably be able to run the framework by following the in-code comments.

## First Step -- Update database
- The [cve-search](https://github.com/cve-search/cve-search) tool is required and assumed updated and executed with the default database location.
- Execute $ ./dvaf.py update (make sure dvaf.py is executable) to fetch and pre-process the DSAs.
- Execute $ python3 ./vendors/debian/DLAmine.py to fetch and pre-process the DLAs.

## Second Step -- Plot
- Execute $python3 All_plots.py .
- With a little bit of luck, you will see a lot of interesting plots. (The current implementation is a bit memory-hungry)
