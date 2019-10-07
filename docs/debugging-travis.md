### Debugging Travis Build

Kritis uses Travis to run CI unit tests [here](https://travis-ci.org/grafeas/kritis).

You can use `Docker` to create similar container environment for local testing.

This is helpful if you cannot reproduce Travis failures in your local dev environment.


1. Find the latest `xenial` image tag at the travis dockerhub [repo](https://hub.docker.com/r/travisci/ci-sardonyx/tags). 
As an example, the latest image tag as of writing is `packer-1564753982-0c06deb6`.

```shell
$ IMAGE="travisci/ci-sardonyx:packer-1564753982-0c06deb6"
```
2. Start a Docker container.

```shell
$ BUILDID="build-$RANDOM"
$ docker run --name $BUILDID -dit $IMAGE /sbin/init
```

3. Run a client and logs into the container
```shell
$ docker exec -it $BUILDID bash -l
```

4. Switch to `travis` user
```shell
$ su - travis
```

5. Check out your pull request and run the unit tests

```shell
$ PR=YOUR_PR_NUM
$
$ git clone --depth=50 https://github.com/grafeas/kritis.git $GOPATH/src/github.com/grafeas/kritis
$ cd $GOPATH/src/github.com/grafeas/kritis
$ git fetch origin +refs/pull/$PR/merge
$ git checkout -qf FETCH_HEAD
$ 
$ make test
```

## Credit
https://stackoverflow.com/questions/21053657/how-to-run-travis-ci-locally/49019950
