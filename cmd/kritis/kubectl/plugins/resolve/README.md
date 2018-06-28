# resolve-tags

resolve-tags replaces tagged images in your Kubernetes yamls with their corresponding digests, and prints the new manifest to STDOUT.
It can be run as a binary or installed as a kubectl plugin.

## kubectl plugin

To install as a kubectl plugin, run:

```
make install-plugin
```

in the top level directory.

You can then run the plugin:

```
kubectl plugin resolve-tags -f <path to file>
```

## resolve-tags binary

resolve-tags can also be run as a binary. 
This is useful if you want to pass in multiple files at a time.
To build the binary, run:

```
make out/resolve-tags
```

in the top level directory.

You can then run the binary:

```
./out/resolve-tags -f <path to file> -f <path to another file>
```
