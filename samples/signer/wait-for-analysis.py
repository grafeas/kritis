#!/usr/bin//python
# Lint as: python3
"""
Polls container analysis api until named container has been scanned for vulnerabilities or timeout
"""
import json
import os
import sys
import time
import re

import requests

from grafeas.grafeas_v1.gapic.enums import DiscoveryOccurrence
from google.cloud.devtools import containeranalysis_v1

def get_resource_url(resource_url):
    """Returns a properly formatted resource_url like:
    https://gcr.io/my-project/my-image@sha256:longhash
    no matter what format you pass in"""
    m = re.match(r"(https://|)(?P<registry>gcr.io)/(?P<path>[^:@]*)(@(?P<digest>sha256:[a-f0-9]*)|)(:(?P<tag>.*)|)", resource_url)
    if m.group('digest') is not None:
        resource_url = "https://{}/{}@{}".format(m.group('registry'), m.group('path'), m.group('digest'))
    else:
        tag = m.group('tag')
        if tag is None:
            tag = "latest"
        registry_api = "https://{}/v2/{}/tags/list".format(m.group('registry'), m.group('path'))
        r = requests.get(registry_api, headers={'Accept': 'application/vnd.docker.distribution.manifest.v2+json'})
        manifests = r.json()['manifest']
        digest = ""
        for key in manifests.keys():
            if tag in manifests[key]['tag']:
                digest = key
                break
        if digest == "":
            raise RuntimeError('could not find digest for image {}'.format(resource_url))
        resource_url = "https://{}/{}@{}".format(m.group('registry'), m.group('path'), digest)

    return resource_url
        
def poll_discovery_finished(resource_url, timeout_seconds, project_id):
    """Returns the discovery occurrence for a resource once it reaches a
    terminal state."""
    # resource_url = 'https://gcr.io/my-project/my-image@sha256:123'
    # timeout_seconds = 20
    # project_id = 'my-gcp-project'

    import time
    from google.cloud.devtools import containeranalysis_v1

    deadline = time.time() + timeout_seconds

    client = containeranalysis_v1.ContainerAnalysisClient()
    grafeas_client = client.get_grafeas_client()
    project_name = grafeas_client.project_path(project_id)

    discovery_occurrence = None
    while discovery_occurrence is None:
        time.sleep(1)
        resource_url = get_resource_url(resource_url)
        filter_str = 'resourceUrl="{}" \
                      AND noteProjectId="goog-analysis" \
                      AND noteId="PACKAGE_VULNERABILITY"'.format(resource_url)
        result = grafeas_client.list_occurrences(project_name, filter_str)
        # only one occurrence should ever be returned by ListOccurrences
        # and the given filter
        for item in result:
            discovery_occurrence = item
        if time.time() > deadline:
            raise RuntimeError('timeout while retrieving discovery occurrence')

    status = DiscoveryOccurrence.AnalysisStatus.PENDING
    while status != DiscoveryOccurrence.AnalysisStatus.FINISHED_UNSUPPORTED \
            and status != DiscoveryOccurrence.AnalysisStatus.FINISHED_FAILED \
            and status != DiscoveryOccurrence.AnalysisStatus.FINISHED_SUCCESS:
        time.sleep(1)
        updated = grafeas_client.get_occurrence(discovery_occurrence.name)
        status = updated.discovery.analysis_status
        if time.time() > deadline:
            raise RuntimeError('timeout while waiting for terminal state')
    return discovery_occurrence

def main(argv):
  if len(argv) > 4:
    raise app.UsageError('Too many command-line arguments.')
  result = poll_discovery_finished(resource_url=argv[1], timeout_seconds=120, project_id=argv[2])
  print "Vulnerability scanning finished on {}".format(resource_url)
  print result


if __name__ == '__main__':
  main(sys.argv)
