# AWS inventory

## Prerequisites
Install python and pip
```bash
$ apt install python-pip
```
Install boto3
```bash
$ apt install python-boto3
```
or
```bash
$ pip install boto3
```
Install pyjq
```bash
$ apt install make automake libtool python-dev
$ pip install pyjq
```
Install openpyxl
```bash
$ apt install python-openpyxl
```
or
```bash
$ pip install openpyxl
```
## Usage
```bash
$ python aws-inventory.py --filename <FILENAME> --region <REGION> --output <FILENAME>
       --filename - filename with resource specifications (YAML)
       --region - aws-region (default: us-east-1)
       --output - write to file (xlsx)
```
## Example
```bash
$ AWS_PROFILE=default python aws-inventory.py -f filter.yaml -o aws-resources.xlsx
```
