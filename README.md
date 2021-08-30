# starwind-vsan-exporter

Prometheus Exporter for Starwind VSAN VSphere Edition. Exports metrics from a Starwind HA node control port (3261) via telnet. Works in a similar way to the blackbox exporter.

You should run this service somewhere and then make sure it has the credentials loaded into the config file (for example a kubernetes secret) then it will go out and scrape the host directly whenever prometheus requests metrics.

Full documentation doesn't really exist yet. If there is some interest I will add a getting started.

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
