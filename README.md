# Suricata Eve Elasticsearch Output Plugin for Suricata 6.0.x

This plugin provides a Suricata Eve output for Elasticsearch. Base on suricata-redis-output: https://github.com/jasonish/suricata-redis-output/tree/6.0

## Building

```
git clone https://github.com/yunsur/suricata-elasticsearch-output.git
cd suricata-elasticsearch-output
cargo build --release
```

## Installing

As there is no standard way (yet) to install Suricata plugins we'll install the
plugin to `/usr/local/lib/suricata/plugins`.

```
mkdir -p /usr/local/lib/suricata/plugins
cp target/release/libelasticsearch_output.so /usr/local/lib/suricata/plugins/
```

Add a section to your `suricata.yaml` that looks like:

```
plugins:
  - /usr/local/lib/suricata/plugins/libelasticsearch_output.so
```

Then set the `filetype` in your `eve` configuration section to
`elasticsearch`.

## Configuration

Add a section to your `suricata.yaml` that looks like:

```
elasticsearch:
  url: "http://localhost:9200"
  index: suricata
  buffer-size: 1024
```
