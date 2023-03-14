<h1 align="center">duplicateRemover</h1>
<h4 align="center">Tool for removing entries which are duplicates from subdomain enumeration</h4>
<p align="center">
  
  <img src="https://img.shields.io/github/watchers/secinto/duplicateRemover?label=Watchers&style=for-the-badge" alt="GitHub Watchers">
  <img src="https://img.shields.io/github/stars/secinto/duplicateRemover?style=for-the-badge" alt="GitHub Stars">
  <img src="https://img.shields.io/github/license/secinto/duplicateRemover?style=for-the-badge" alt="GitHub License">
</p>

Developed by Stefan Kraxberger (https://twitter.com/skraxberger/)  

Released as open source by secinto GmbH - https://secinto.com/  
Released under Apache License version 2.0 see LICENSE for more information

Description
----
duplicateRemover is a GO tool which removes duplicte subdomain entries from enumeration. Very often a lot of 
entries resolve to the same host and same information. Currently our assumption is that these "useless" subdomains 
are added due to SEO optimization and don't provide any relevant information for penetration testing. It on the other
hand increases the amount of requests and time required for the recon phase. Thus, this tool removes these duplicates based
on the returned content.

# Installation Instructions

`simpleFinder` requires **go1.20** to install successfully. Run the following command to get the repo:

```sh
git clone https://github.com/secinto/duplicateRemover.git
cd duplicateRemover
go build
go install
```

or the following to directly install it from the command line:

```sh
go install -v github.com/secinto/simpleFinder/cmd/duplicateRemover@latest
```

# Usage

```sh
duplicateRemover -help
```

This will display help for the tool. Here are all the switches it supports.


```console
Usage:
  ./duplicateRemover [flags]

Flags:
   -f,                   input file containing the data to be stored in elastic/logstash
   -i                    the index under which the content should be stored
   -p                    project name which will be added as additional information to the data
   -h                    host name which will be added as additional information to the data
