# Automata

<p align="center"><img src="./imgs/automata-logo.png" width="400" height="415"></p>

## What

Automata is a tool to detect errors early and measure the Effectiveness of SIEM rules against the behaviors that the rule was developed to work against, ensuring that the whole process of data collection, parsing, and query of security data is working properly and alert when things don't work as intended.

Read more about Automata in our [introductory blog post](https://blog.3coresec.com/2021/08/detection-as-code-dac-challenges.html).

[@_w0rk3r](https://twitter.com/_w0rk3r/) and [@heyibrahimkhan](https://twitter.com/heyibrahimkhan) are the primary authors of Automata.

## Why

Security monitoring has a challenge that is hard to overcome. 
Changes occur daily in a modern enterprise, and some are not that well managed, and if they are internal, service teams aren't involved most of the time. 

Some common examples are: 

* Change in log formats
  * Products are frequently updated and seeing as some require custom parsers due to their format, these updates can easily break the parsing, effectively breaking or affecting the detections.

* The monitored system doesn't have the required configurations applied.
  * Some detections need custom audits and policies to work. And sometimes, this is not defined in the baseline policies, causing gaps in the security monitoring.

* Software Bugs
  * New versions of the products used on our detection pipeline can introduce bugs that will cause errors in our receiving/indexing pipeline. It is of critical importance that those are identified as soon as possible.

Once a problem is identified early, SOC teams can fix these problems before this impacts the detection and response program.

# Setup

<p align="center"><img src="./imgs/automata-workflow.png" width="700" height="598"></p>

## Tech Stack

This project uses:

* Elastic
* Caldera
* Python

<img src="./imgs/automata-mascot-02.png" width="300" height="624" align="right">

## Configuration File

To get started, you need to setup a `config.py` in the utils directory, based on the [example config](/utils/configfile.py.example) and modify the following variables:

* `CALDERA_URL`: The URL of the Caldera Server
* `CALDERA_API_KEY`: The API Key for Caldera
* `deployment_type`: The Deployment Type. possible values: "onprem", "cloud"

Variables that should be set if using Elastic Cloud

* `kibana_host`: The URL to Kibana
* `cloud_id`: Elastic Cloud ID

Variables that should be set if using Elastic on-prem

* `kibana_onprem`: The URL to On-prem Kibana
* `elasticsearch_onprem`: The URL to On-Prem Elasticsearch

Password Variables:

* `http_auth_user`: Elastic User
* `http_auth_pass`: Elastic Password

# Usage

## See it in action! 

In the example below we'll task Automata with the goal of validating an AWS S3 detection, where logging on a bucket is disabled:

[![asciicast](https://asciinema.org/a/429661.svg)](https://asciinema.org/a/429661)

## Run Modes

There are currently two modes of execution: `Batch` and `Concurrent`.

1. `Batch` executes a list of abilities, one by one.
2. `Concurrent` executes a list of abilities concurrently.

### 1. Batch:

**Required params:**

* `-t`: The Target Caldera Agent
* `-rf`: The relations file containg the ruleid to abilityid links
* `-b`: Batch Mode Switch

**Example:**

```
python .\main.py -t rkersr -rf .\relations.json -b
```

### 2. Concurrent:

**Required params:**

* `-bc`: Switch that enables "Concurrent" execution type.
* `-t`: The Target Caldera Agent
* `-rf`: The relations file containg the ruleid to abilityid links

**Example:**

```
python .\main.py -t hvozis -rf .\relations.json -bc
```

### Sample output

<p align="center"><img src="./imgs/automata-1.png"></p>

### Sample PDF Report

<p align="center"><img src="./imgs/report.png"></p>

## Outputs

Automata generates a PDF report as well as a CSV file with the results of its last execution. By default these files will be stored in the directory where you ran Automata. You can specify a different output directory using the `-o` switch.

# Feedback

Found this interesting? Have a question/comment/request? Let us know!

Feel free to open an [issue](https://github.com/3CORESec/Automata/issues) or ping us on [Twitter](https://twitter.com/3CORESec).

[![Twitter](https://img.shields.io/twitter/follow/3CORESec.svg?style=social&label=Follow)](https://twitter.com/3CORESec)
