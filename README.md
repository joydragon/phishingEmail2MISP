# phishingEmail2MISP

This script is meant to parse an email file (just .txt for now) that's considered *malicious email*, and generate an event on a MISP (http://www.misp-project.org/) instance about it.


## Requirements

Needs __jq__ (https://stedolan.github.io/jq/) as a JSON parser.

Needs __pup__ (https://github.com/EricChiang/pup/releases/) as a HTML parser.


## Preparation

The script is meant to fail at first because it's missing some configuration.

* **Line 8**: Flag to set if the attachments will be save to the file system
* **Line 9**: Folder to save the attachments to (defaults to current folder)
* **Line 362**: URL or IP for the target MISP instance
* **Line 363**: Authorization Key for the MISP account (https://www.circl.lu/doc/misp/automation/#automation-key)

After this setup, you can delete **Lines 356-360**, then run the actual script.


## Usage

As a bash script you don't need to install it, just run the bash script as a normal user:

`
$ phishingEmail2MISP.sh [email_file]
`


## ToDo

Still there are some features that I want to implement like:

* Connect to well-known online scanners like VirusTotal (https://virustotal.com/) or Hybrid-Analysis (https://www.hybrid-analysis.com/)
