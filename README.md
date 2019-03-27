Platform Kubernetes Windows Nodeup
===

This repository contains an equivalent kops nodeup script in PowerShell for Windows nodes in AWS.

## Overview
This PowerShell script consists primarily of two main parts, the first being the download and installation of all
necessary resources, including binaries. The second consists of the installation of Windows services and start of those
services in order to join the node to the cluster.

### Installation Part
The script starts by gathering some information about itself via AWS's metadata service and via the kops-generated
userdata script. Then it pulls additional information from the kops S3 state store backend including the cluster spec
and kubeconfig files.

In parallel the script will also download and install the necessary binaries and Docker infrastructure images onto the
system.

### Execution Part
Once the node has been prepared the script will begin to start the required kubernetes services, starting with
`kubelet`. We need to start kubelet first in order to register the node as flanneld needs to pull information from the
cluster about the node. Once kubelet is started we start `flanneld`, then acquire the source-vip information for use by
`kube-proxy`. Then we start kube-proxy and at that point the node should be good to go!