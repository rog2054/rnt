![RNT Logo](/static/icons/favicon-128x128.png)
# RNT

## ❓ Purpose

**tldr : Verify the LIVE STATE of various parts of your Network**

We can all look at (or maybe get sent automatically by some monitoring tool) config diffs and see what has changed, but what about the actual real-world live state of things like routing table when you are using dynamic routing protocols?

This utility gives you a quick and repeatable way to verify the Live State of several aspects of your corporate network.

It is certainly NOT intended to be 'yet another' monitoring tool ... although they have their uses too.

Think of this as a way to quickly verify the things that your team might usually take 20 minutes to check manually. In our initial testing we ran over 100 individual tests in single test run under 30 seconds, and there is potential to increase the performance.

Some suggested use cases are:
1. Before & After a making a configuration change, to verify that nothing else has been accidentally broken as a side-effect.
2. When a WAN circuit or network device fails, to show you the impact (ie where routing has changed).

It is provided as a ready-built docker image 🐳 and can be run on either Windows or Linux.

Once installed you and your team can access it via a simple web interface.

***

## Features

* Define once, run-many approach to configuration of RNT
* Only requires read-only SSH access (using a read-only account is strongly recommended)
* Any passwords stored in the RNT database are encrypted
* The RNT Database (app configuration and test results) is a single file which can be easily backed up by copy/paste - no SQL knowledge or tools are required
* Multi-threaded concurrent SSH sessions
* View a simple Pass/Fail AND the actual cli output that was taken during the test execution
* Simple-mode comparison of previous test outcomes (by Pass/Fail results)
* Exact-mode comparison of prevoius test outcomes (by actual cli output)
* Easy web-interface, ideal for your network engineers who love a Cisco device but who are not programmers!

***

## 🚀 Quick Install

### Start in 3 steps ###
1. Download the docker-compose.yml file from this repo.
2. Run docker compose up, this will download the latest stable image from Docker Hub and run the image.
3. Access at http://yourdockerhostip:5000

*See below for [detailed install instructions](#detailedinstallsteps) for Windows or Linux*


***
<a id="detailedinstallsteps"></a>
## 💡 Detailed Install Instructions

### Setup in Windows

1. Download docker-compose.yml file from this repo into a folder, eg c:\rnt
2. If you do not have Docker already then download, install, and run [Docker Desktop](https://www.docker.com/products/docker-desktop/) for Windows
3. Identify your machine IP address `ipconfig` (eg 10.10.10.24)
4. From the command prompt, build and run the docker image
     c:\rnt> `docker compose up -d`


### Setup in Linux
(based on a fresh minimal server install of Ubuntu, but any similar distro should be a similar process)

1. Download docker-compose.yml file from this repo into a folder, eg c:\rnt
2. Install Docker Compose
`sudo apt-get install docker-compose`
 
   Add the current linux user to the docker group `sudo usermod -aG docker ${USER}`

   Logoff then logon again for the new group membership to apply
3. Identify your machine IP address `ip a` (eg 10.10.10.24)
4. Build and run the docker image `docker-compose up -d`

***

## 👪 User Guide

### The RNT web interface


From a web browser go to http://ipaddress:5000 from step 3 above, eg `http://10.10.10.24:5000` 

*For simplicity the ip address 10.10.10.24 will be used throughout the remainder of this Readme but remember to replace it with your own ip!*

#### First Run
When you first run the app and go to the page, as no users exist within the app you will be prompted to create a username and password.
Subsequent visits to the home url will display the login page.

#### Adding Users
Once logged in there is a menu option to create additional user logons.
Users can change their own password (to something private) from within the app.

![screenshot](/screenshots/login_page.png)

### Overview of the RNT stages

1. Add your device authentication details : a read-only account with SSH access to the devices to run 'show' commands is all that is necessary
2. Define your network devices (Currently Cisco IOS, Cisco NXOS and Cisco ACI devices are supported)
3. Add one of more tests in any of the Test Categories that you are interested in:
 - BGP AS-path test
 - Traceroute test
 - SFP TxRx transceiver test
 - ACI iTraceroute test
4. Run the tests
5. View the results

![screenshot](/screenshots/rnt-stages.png)


### More detailed documentation/guides are within the app itself

***

## Future Improvements
This is a quick project I put together for myself and my team to use at work. I am not a professional developer and certainly not a front-end designer either, however I am an ideas person and I know a bit about corporate networks having worked in the industry for 25+ years.

I may implement some of these improvements at some point however others are welcome to collaborate and contribute updates in the spirit of open source code.

With that said here are some future improvements I can think of. These are listed in no particular order.

- [ ] Add other types of test. The above 4 started off as 2 and then 1, so i'm sure more will be added as the need arises. If you have any ideas for different tests please drop me a note and we can maybe collaborate on adding that functionality (don't worry if you're not a coder, i also need things like cli output examples to add a new test)
- [ ] Support for other vendors. This isn't currently a high-priority to me as our environment is mainly Cisco so this app obviously focuses on Cisco, however it has been written in a way to allow use with other vendors also (basically any that netmiko supports, which is a lot of the main vendors) so i'm not against working on this as a lower-priority addition if enough people will benefit from it.


## 🙏 Acknowledgements

| | |
| :------------- |:-------------| 
| [**NetMiko**](https://github.com/ktbyers/netmiko) | Multi-vendor library to simplify CLI connections to network devices |
| [**Flask**](https://flask.palletsprojects.com/en/stable/) | Flask is a lightweight WSGI web application framework |
| [**SQLite**](https://www.sqlite.org/) | A small, fast, self-contained, high-reliability, full-featured, SQL database engine |
| [**Python**](https://www.python.org/) | A popular programming language suitable for a wide range of abilities and use cases|
| [**Docker**](https://www.docker.com/) | An easy way to package code for use on different systems without dependency issues

***

## 💀 Privacy

- The only data saved by RNT is saved into the .db file which is stored locally on your docker host machine (outside of the docker container)
- This .db file contains passwords (encrypted), test definitions (created by you), test results (from the test execution runs)
- I strongly recommened to only use SSH credentials with read-only access to your equipment for RNT, as that is all it requires

***
