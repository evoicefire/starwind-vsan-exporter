# starwind-vsan-exporter

Prometheus Exporter for Starwind VSAN VSphere Edition. Exports metrics from a Starwind HA node control port (3261) via telnet. Works in a similar way to the blackbox exporter.

You should run this service somewhere and then make sure it has the credentials loaded into the config file (for example a kubernetes secret) then it will go out and scrape the host directly whenever prometheus requests metrics.

Full documentation doesn't really exist yet. If there is some interest I will add a getting started. Create an Issue if you are interested and tag me in it.

# ToDo

* Docs
