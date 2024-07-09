# ConnStatsTcpreplay
CoonStatsDynamicByTime aggregates packets into flows and generates statistics dynamically every user defined time threshold has elapsed. Currently is valid for scenarios where observed traffic is only ingress.


# Requirements
Inside Requirements folder can be found the installed libraries and dependencies to run the programs in Ubuntu 22.04.3 LTS

To reinstall them in your system use the following comands:

dpkg --get-selections < ubuntu_installed_packages.txt
apt-get dselect-upgrade

pip install -r requirements_python.txt

with the go.mod and go.sum files copied in the environments run:
go mod download


# Run the programs
To run the program, go to the cmd folder.

cd cmd
sudo go run connstats.go [options]

current options are:

-i <interface> : network interface to attach the ebpf program, by default is enp0s8

-t <int>       : level of time agregation in ms, number of elapsed milliseconds that triggers the statistics eviction  



To run the python program go to pythonapp folder, use the server option to enter the ip of the machine running the probe. Know you can also copy the pythonapp folder to a remote location that has connectivity with the machine running the probe to extend the solution.  
cd pythonapp
python3 main.py [options]

current options are:

--server <server_ip> : ip of the machine running the probe, mandatory option
--rtime <refresh_time> : refresh time in seconds to collect the statistics from the probe, 10 sec by default
example: python3 main.py --server_ip 192.168.1.204 --rtime 7

