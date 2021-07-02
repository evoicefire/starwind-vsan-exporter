# starwind-vsan-exporter

Exporter for Starwind VSAN VSphere Edition

# ToDo

* Config file
* Config parsing for a list of hosts
* each host is selectable using a get parameter
* selectable by name - blackbox exporter style
* Each stanza has: IP, username, password
* Need to configure all the metrics for starwind
* Metric for each parameter from starwind
  * Iterate through devices and set metrics that are present
  * Leave metrics that aren't present unset
