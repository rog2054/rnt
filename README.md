![RNT Logo](./static/icons/favicon-128x128.png)
# RNT

## ❓ Purpose

**tldr : Verify the LIVE STATE of various parts of your Network**

We can all look at (or maybe get sent automatically by some monitoring tool) config diffs and see what has changed, but what about the actual real-world live state of things like routing table when you are using dynamic routing protocols?

This utility gives you a quick and repeatable way to verify the Live State of several aspects of your corporate network.

It is certainly NOT intended to be 'yet another' monitoring tool ... although they have their uses too.

Think of this as a way to quickly verify the things that your team might usually take 20 minutes to check manually. In our initial testing we ran over 100 individual tests in single test run under 30 seconds, and there is potential to increase the performance.

Some suggested use cases are:
1. Run a RNT test suite Before & After making a configuration change to verify that nothing else has been accidentally impacted as a side-effect.
2. Run RNT tests when a WAN circuit or network device fails to give you a quick idea of the impact so you can focus your efforts on any workarounds that might be needed to restore service/performance to the business (or pat yourselves on the back because everything failed over flawlessly, yey!).

It is provided as a ready-built docker image 🐳 and can be run on either Windows or Linux.

Once installed you and your team can access it via a simple web interface.

***

## Features

* Define once, run-many approach to reduce duplicated effort
* Only requires read-only SSH access (using a read-only account is strongly recommended)
* Passwords stored in the RNT database are encrypted as standard
* The RNT Database (app configuration and test results) is a single file which can be easily backed up by copy/paste or standard backup tools - no SQL-specific tools or knowledge are required
* Multi-threaded concurrent SSH sessions for awesome performance
* View the cli output from the test execution - so your technical team can still give a technical opinion on what is happening on your network, just now they can do it faster!
* Simple-mode comparison of previous test outcomes (by Pass/Fail results)
* Exact-mode comparison of previous test outcomes (by Actual CLI output)
* Easy web-interface, ideal for your network engineers who love a Cisco device but who are not programmers...

***

## 🚀 Quick Install

### Start in 3 steps ###
1. Download the docker-compose.yml file from this repo.
2. Run docker compose up, this will download the latest stable image from Docker Hub and run the image.
3. Access at `http://yourdockerhostip:5000`

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

### Optional Setup suggestion to make things nicer
Put this behind a load balancer/WAF/proxy of your choice (F5, nginx, NPM, etc) so it can have a nice url and also so people don't need to put the port number on the end.
eg: https://rnt.yourdomain.com instead of https://10.10.10.24:5000

***

## 👪 User Guide

### The RNT web interface


From a web browser go to https://ipaddress:5000 from step 3 above, eg `https://10.10.10.24:5000` 
Note HTTPS not HTTP.

*For simplicity the ip address 10.10.10.24 will be used throughout the remainder of this Readme but remember to replace it with your own ip!*

#### First Run
When you first run the app and go to the page, as no users exist within the app you will be prompted to create a username and password.

Subsequent visits to the home url will display the login page.

#### Adding Users
Once logged in there is a menu option to create additional user logons.
Users can change their own password (to something private) from within the app.

After the 'admin' initial user, the next user you create is automatically a 'demo' user. Choose whatever username/password you like for this.
The 'demo' user is intended to be used for demonstrating the utility. Most of its results are only visible when logged in as this 'demo' user (so it doesn't clutter the main test results for everyone else!).

If you don't feel the need for this, just create a demo user and then don't use it :)

Ensure your actual users start with user no 3.


### Overview of the RNT stages

1. Add your device authentication details : a read-only account with SSH access to the devices to run 'show' commands is all that is necessary
2. Define your network devices (Currently Cisco IOS, Cisco NXOS and Cisco ACI devices are supported)
3. Add one of more tests in any of the Test Categories that you are interested in:
 - BGP AS-path test
 - Traceroute test
 - Ping test
 - SFP TxRx transceiver test
 - ACI iTraceroute test
4. Run the tests
5. View the results


### More detailed documentation/guides are within the app itself

***

## Future Improvements
This is a quick project I put together for myself and my team to use at work. I am not a professional developer and certainly not a front-end designer either, however I am an ideas person and I know a bit about corporate networks having worked in the industry for 25+ years.

I may implement some of these improvements at some point however others are welcome to collaborate and contribute updates in the spirit of open source code.

With that said here are some future improvements I can think of. These are listed in no particular order.

- [X] Per User timezone preference and timezone-adaptive results pages.
- [X] Assign tests into custom Test Groups and run tests for just that Test Group, rather than ALL Tests (All Tests remains a valid method).
- [X] New test category 'Custom Show Command' to allow tests to be created that aren't the predefined as-path/ping/traceroute etc.
- [ ] Make the UI multi-lingual, so each user can set their preferred language.
- [ ] Support for other vendors. This isn't currently a high-priority to me as our environment is mainly Cisco so this app obviously focuses on Cisco initially, however it has been written in a way to allow adding tests for other vendors equipment also (basically any that netmiko supports - which is a lot of the main vendors) so i'm not against working on this as a lower-priority addition if enough people will benefit from it.


## 🙏 Acknowledgements

| | |
| :------------- |:-------------| 
| [**NetMiko**](https://github.com/ktbyers/netmiko) | Multi-vendor library to simplify CLI connections to network devices |
| [**Flask**](https://flask.palletsprojects.com/en/stable/) | Flask is a lightweight WSGI web application framework |
| [**SQLite**](https://www.sqlite.org/) | A small, fast, self-contained, high-reliability, full-featured, SQL database engine |
| [**Python**](https://www.python.org/) | A popular programming language suitable for a wide range of abilities and use cases |
| [**Docker**](https://www.docker.com/) | An easy way to package code for use on different systems without dependency issues |

***

## 💀 Privacy

- The only data saved by RNT is saved into the .db file which is stored locally on your docker host machine (outside of the docker container)
- This .db file contains passwords (encrypted), test definitions (created by you), test results (from the test execution runs)
- I strongly recommened to only use SSH credentials with read-only access to your equipment for RNT, as that is all it requires

***
