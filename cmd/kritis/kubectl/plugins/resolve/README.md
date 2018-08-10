# resolve-tags

resolve-tags replaces tagged images in your Kubernetes yamls with their corresponding digests, and prints the new manifest to STDOUT.
It can be run as a binary or installed as a kubectl plugin.

## Installation

## Mac OS X

```shell
curl -LO https://storage.googleapis.com/resolve-tags/latest/resolve-tags-darwin-amd64.tar.gz && \
  RESOLVE_TAGS_DIR=$HOME/.kube/plugins/resolve && \
  mkdir -p $RESOLVE_TAGS_DIR && tar -C $RESOLVE_TAGS_DIR -xzf resolve-tags-darwin-amd64.tar.gz && \
  mv $RESOLVE_TAGS_DIR/resolve-tags-darwin-amd64 $RESOLVE_TAGS_DIR/resolve-tags && \
  sudo cp $RESOLVE_TAGS_DIR/resolve-tags /usr/local/bin/
```

## Linux

```shell
curl -LO https://storage.googleapis.com/resolve-tags/latest/resolve-tags-linux-amd64.tar.gz && \
  RESOLVE_TAGS_DIR=$HOME/.kube/plugins/resolve && \
  mkdir -p $RESOLVE_TAGS_DIR && tar -C $RESOLVE_TAGS_DIR -xzf resolve-tags-linux-amd64.tar.gz && \
  mv $RESOLVE_TAGS_DIR/resolve-tags-linux-amd64 $RESOLVE_TAGS_DIR/resolve-tags && \
  sudo cp $RESOLVE_TAGS_DIR/resolve-tags /usr/local/bin/
```

## Quickstart

### Running the resolve-tags kubectl plugin

You can run the plugin as follows:

```
kubectl plugin resolve-tags -f <path to file>
```

To apply subsitutions as you would using `kubectl apply -f`, you can run:

```
kubectl plugin resolve-tags -f <path to file> --apply true
```

Note: The plugin can only resolve one file at a time.
If you need to resolve more than one file at the time, consider using the binary.

## Running the resolve-tags binary

You can run the resolve-tags binary as follows:

```
resolve-tags -f <path to file> -f <path to another file>
```
To apply subsitutions using `kubectl apply -f`, you can run:
```
resolve-tags -f <path to file> -a
```
This will apply the digest to the objects defined in file.
