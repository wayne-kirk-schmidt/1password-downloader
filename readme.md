1Password Downloader
====================

This is a downloader for 1Password events using the op command line

Installing the Scripts
=======================

The scripts are command line based, designed to be used within a batch script or DevOPs tool such as Chef or Ansible.
Each script is a python3 script, and the complete list of the python modules will be provided to aid people using a pip install.

You will need to use Python 3.6 or higher and the modules listed in the dependency section.  

The steps are as follows: 

    1. Download and install python 3.6 or higher from python.org. Append python3 to the LIB and PATH env.

    2. Download and install git for your platform if you don't already have it installed.
       It can be downloaded from https://git-scm.com/downloads
    
    3. Open a new shell/command prompt. It must be new since only a new shell will include the new python 
       path that was created in step 1. Cd to the folder where you want to install the scripts.
    
    4. Execute the following command to install pipenv, which will manage all of the library dependencies:
    
        sudo -H pip3 install pipenv 
 
    5. Clone this repository. This will create a new folder
    
    6. Change into this folder. Type the following to install all the package dependencies 
       (this may take a while as this will download all of the libraries it uses):

        pipenv install
        
Dependencies
============

See the contents of "pipfile"

Script Names and Purposes
=========================

    1. the scripts in ./bin - 
        ./bin/1password_downloader.py

    2. show the help page
        ./bin/1password_downloader.py -h

    3. specify configuration file to use
        ./bin/1password_downloader.py -c ./etc/1password_downloader.cfg

    4. download the last 10 days of events
        ./bin/1password_downloader.py -c ./etc/1password_downloader.cfg -o 10

    5. specify script verbosity ( default is 0 or silent save errors )
        ./bin/1password_downloader.py -c ./etc/1password_downloader.cfg -v 5

To Do List:
===========

* add posting to sources

License
=======

Copyright 2021 Wayne Kirk Schmidt

Licensed under the GNU GPL License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    license-name   GNU GPL
    license-url    http://www.gnu.org/licenses/gpl.html

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Support
=======

Feel free to e-mail me with issues to: wayne.kirk.schmidt@gmail.com
I will provide "best effort" fixes and extend the scripts.
